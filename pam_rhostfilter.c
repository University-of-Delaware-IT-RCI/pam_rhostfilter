//
// pam_rhostfilter.c
//
// PAM module that implements ONLY the account mgmt function and checks
// the remote host associated with the connection attempt against a user-defined
// list of allowed/denied hostnames or IPs.
//

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <pwd.h>
#include <unistd.h>
#include <syslog.h>

#ifdef PAM_BYHOST_MODULE
#   include <security/pam_modules.h>
#   ifdef HAVE_PAM_MODUTIL
#       include <security/pam_modutil.h>
#   endif
#   ifdef PAM_BYHOST_IS_MACOSX
#       include <security/pam_appl.h>
#   endif
#   ifdef HAVE_PAM_EXT
#       include <security/pam_ext.h>
#   else
#       define pam_syslog(PH, LVL, FMT, ...)    syslog(LVL, FMT, ##__VA_ARGS__)
#   endif
#   define LOG(F, ...) syslog(LOG_DEBUG, F, ##__VA_ARGS__)
#else
#   define PAM_AUTH_ERR     -1
#   define PAM_SUCCESS       0
#   define PAM_PERM_DENIED   1
#   define LOG(F, ...) fprintf(stderr, F "\n", ##__VA_ARGS__)
#endif

//

#ifndef PAM_BYHOST_CONF_FILENAME
#define PAM_BYHOST_CONF_FILENAME    ".pam_rhostfilter.conf"
#endif
const char          *pam_rhostfilter_conf_filename = PAM_BYHOST_CONF_FILENAME;

const char*
__pam_rhostfilter_default_conf_file(
    uid_t       target_uid
)
{
    static char *default_conf_file = NULL;
    
    if ( ! default_conf_file ) {
        struct passwd   *user_info = getpwuid(target_uid);
        
        if ( user_info && user_info->pw_dir ) {
            size_t      default_conf_file_len = strlen(user_info->pw_dir) + 1 + strlen(pam_rhostfilter_conf_filename) + 1;
            
            if ( (default_conf_file = malloc(default_conf_file_len)) ) {
                snprintf(default_conf_file, default_conf_file_len, "%s/%s", user_info->pw_dir, pam_rhostfilter_conf_filename);
            }
        }
    }
    return default_conf_file;
}

bool
__pam_rhostfilter_can_use_conf_file(
    const char      *conf_file,
    uid_t           conf_file_owner
)
{
    struct stat     finfo;
    
    if ( lstat(conf_file, &finfo) != 0 ) return false;
    if ( ! S_ISREG(finfo.st_mode) ) { errno = EINVAL; return false; }
    if ( (conf_file_owner != 0) && (finfo.st_uid != conf_file_owner)) { errno = EACCES; return false; }
    if ( (finfo.st_mode & (S_IRWXG | S_IRWXO)) != 0 ) { errno = EPERM; return false; }
    return true;
}

//

#ifdef PAM_BYHOST_IPV4_ONLY
#define PAM_BYHOST_AI_FAMILY    AF_INET;
#else
#define PAM_BYHOST_AI_FAMILY    AF_UNSPEC;
#endif

bool
__pam_rhostfilter_addr_match(
    struct addrinfo     *addr1,
    struct addrinfo     *addr2,
    int                 prefix_len
)
{
    // To hold the prefix bit masks when needed:
    uint32_t            ipv4_mask = 0;
    uint32_t            ipv6_mask[4] = { 0, 0, 0, 0 };
    
    // Local copies of the address structures so we don't overwrite
    // the original when applying prefix masks:
    union {
        struct sockaddr_in6 ipv6;
        struct sockaddr_in  ipv4;
    } ADDR1, ADDR2;
    
    // Only used when compiled for conf file verification:
    int                 addr1_idx = 0;
    
    if ( ! addr1 || ! addr2 ) return false;
    
    // What's the prefix length for these comparisons?
    LOG("[INFO]        prefix length = %d", prefix_len);
    
    if ( prefix_len >= 0 ) {
#ifndef PAM_BYHOST_IPV4_ONLY
        if ( prefix_len <= 128 ) {
            // Prefix length is acceptable for an IPv6 address, so
            // generate the bit mask now:
            int             i = 0, p = prefix_len;
        
            while ( p >= 32 ) {
                // Full 32-bit words:
                ipv6_mask[i++] = 0xffffffff;
                p-= 32;
            }
            if ( p > 0 ) {
                // If there are any bits left, they belong in the 
                // MSB end of the next word:
                ipv6_mask[i++] = htonl(0xffffffff << (32 - p));
                // Pad with zeroes if necessary:
                while ( i < 4 ) ipv6_mask[i++] = 0;
            }
            LOG("[INFO]            IPv6 mask: 0x%08x%08X%08X%08X", ntohl(ipv6_mask[0]), ntohl(ipv6_mask[1]), ntohl(ipv6_mask[2]), ntohl(ipv6_mask[3]));
        }
#endif
        if ( prefix_len <= 32 ) {
            // Prefix length is acceptable for an IPv4 address, so
            // generate the bit mask now:
            ipv4_mask = htonl(0xffffffff << (32 - prefix_len));
            LOG("[INFO]            IPv4 mask: 0x%08x", ntohl(ipv4_mask));
        }
    }

    // Loop over addr1:
    while ( addr1 ) {
        bool            should_check_addr2 = true;
        
        // Copy the address:
        memcpy(&ADDR1, addr1->ai_addr, addr1->ai_addrlen);
        
        //
        // If there's a prefix length, then let's go ahead and apply it
        // to the address:
        //
        if ( prefix_len >= 0 ) {
            switch ( addr1->ai_family ) {
                case AF_INET:
                    if ( prefix_len > 32 ) {
                        LOG("[ERR ]        Invalid IPv4 prefix length: %d",  prefix_len);
                        should_check_addr2 = false;
                    } else if ( prefix_len >= 0 ) {
                        struct sockaddr_in  *ipaddr = (struct sockaddr_in*)&ADDR1;
                        
                        ipaddr->sin_addr.s_addr &= ipv4_mask;
                    }
                    break;
                
                case AF_INET6:
                    if ( prefix_len > 128 ) {
                        LOG("[ERR ]        Invalid IPv6 prefix length: %d",  prefix_len);
                        should_check_addr2 = false;
                    } else if ( prefix_len >= 0 ) {
                        struct sockaddr_in6 *ipaddr = (struct sockaddr_in6*)&ADDR1;
                        uint64_t            *as_uint64 = (uint64_t*)&ipaddr->sin6_addr.s6_addr;
                        
                        as_uint64[0] &= ipv6_mask[0];
                        as_uint64[1] &= ipv6_mask[1];
                    }
                    break;
            }
        }
#ifndef PAM_BYHOST_MODULE
        switch ( addr1->ai_family ) {
            case AF_INET: {
                struct sockaddr_in  *ipaddr = (struct sockaddr_in*)&ADDR1;
                uint8_t             *as_uint8 = (uint8_t*)&ipaddr->sin_addr.s_addr;
                
                LOG("[INFO]        %-3d %hhu.%hhu.%hhu.%hhu", addr1_idx, as_uint8[0], as_uint8[1], as_uint8[2], as_uint8[3]);
                break;
            }
            case AF_INET6: {
                struct sockaddr_in6 *ipaddr = (struct sockaddr_in6*)&ADDR1;
                uint16_t            *as_uint16 = (uint16_t*)&ipaddr->sin6_addr.s6_addr;
                
                LOG("[INFO]        %-3d %04hx:%04hx:%04hx:%04hx:%04hx:%04hx:%04hx:%04hx", addr1_idx, ntohs(as_uint16[0]), ntohs(as_uint16[1]), ntohs(as_uint16[2]), ntohs(as_uint16[3]), ntohs(as_uint16[4]), ntohs(as_uint16[5]), ntohs(as_uint16[6]), ntohs(as_uint16[7]));
                break;
            }
        }
#endif
        if ( should_check_addr2 ) {
            struct addrinfo *addr2_copy = addr2;
            int             addr2_idx = 0;
            
            
            //
            // Now let us loop over addr2_copy:
            //
            while ( addr2_copy ) {
                //
                // Matching address family?
                //
                if ( addr1->ai_family == addr2_copy->ai_family ) {
                    bool        should_compare = true;
                    
                    // Copy the address:
                    memcpy(&ADDR2, addr2_copy->ai_addr, addr2_copy->ai_addrlen);
                    
                    //
                    // If there's a prefix length, then let's go ahead and apply it
                    // to the address:
                    //
                    if ( prefix_len >= 0 ) {
                        switch ( addr2_copy->ai_family ) {
                            case AF_INET:
                                if ( prefix_len > 32 ) {
                                    should_compare = false;
                                } else if ( prefix_len >= 0 ) {
                                    struct sockaddr_in  *ipaddr = (struct sockaddr_in*)&ADDR2;
                        
                                    ipaddr->sin_addr.s_addr &= ipv4_mask;
                                }
                                break;
                
                            case AF_INET6:
                                if ( prefix_len > 128 ) {
                                    should_compare = false;
                                } else if ( prefix_len >= 0 ) {
                                    struct sockaddr_in6 *ipaddr = (struct sockaddr_in6*)&ADDR2;
                                    uint64_t            *as_uint64 = (uint64_t*)&ipaddr->sin6_addr.s6_addr;
                        
                                    as_uint64[0] &= ipv6_mask[0];
                                    as_uint64[1] &= ipv6_mask[1];
                                }
                                break;
                        }
                    }
#ifndef PAM_BYHOST_MODULE
                    switch ( addr2_copy->ai_family ) {
                        case AF_INET: {
                            struct sockaddr_in  *ipaddr = (struct sockaddr_in*)&ADDR2;
                            uint8_t             *as_uint8 = (uint8_t*)&ipaddr->sin_addr.s_addr;
                
                            LOG("[INFO]            %-3d %hhu.%hhu.%hhu.%hhu", addr2_idx, as_uint8[0], as_uint8[1], as_uint8[2], as_uint8[3]);
                            break;
                        }
                        case AF_INET6: {
                            struct sockaddr_in6 *ipaddr = (struct sockaddr_in6*)&ADDR2;
                            uint16_t            *as_uint16 = (uint16_t*)&ipaddr->sin6_addr.s6_addr;
                
                            LOG("[INFO]            %-3d %04hx:%04hx:%04hx:%04hx:%04hx:%04hx:%04hx:%04hx", addr2_idx, ntohs(as_uint16[0]), ntohs(as_uint16[1]), ntohs(as_uint16[2]), ntohs(as_uint16[3]), ntohs(as_uint16[4]), ntohs(as_uint16[5]), ntohs(as_uint16[6]), ntohs(as_uint16[7]));
                            break;
                        }
                    }
#endif
                    if ( should_compare ) {
                        //
                        // Actually do a comparison now:
                        //
                        switch ( addr1->ai_family ) {
                            case AF_INET: {
                                struct sockaddr_in  *A1 = (struct sockaddr_in*)&ADDR1;
                                struct sockaddr_in  *A2 = (struct sockaddr_in*)&ADDR2;
                                if ( A1->sin_addr.s_addr == A2->sin_addr.s_addr ) {
                                    LOG("[INFO]                IPv4 MATCH!");
#ifdef PAM_BYHOST_MODULE
                                    return true;
#endif
                                }
                                break;
                            }
                            case AF_INET6: {
                                struct sockaddr_in6 *A1 = (struct sockaddr_in6*)&ADDR1;
                                struct sockaddr_in6 *A2 = (struct sockaddr_in6*)&ADDR2;
                                uint64_t            *A1_as_uint64 = (uint64_t*)&A1->sin6_addr.s6_addr;
                                uint64_t            *A2_as_uint64 = (uint64_t*)&A2->sin6_addr.s6_addr;
                                if ( (A1_as_uint64[0] == A2_as_uint64[0]) && (A1_as_uint64[1] == A2_as_uint64[1]) ) {
                                    LOG("[INFO]                IPv6 MATCH!");
#ifdef PAM_BYHOST_MODULE
                                    return true;
#endif
                                }
                                break;
                            }
                        }
                    }
                }
                addr2_idx++;
                addr2_copy = addr2_copy->ai_next;
            }
        }
        addr1_idx++;
        addr1 = addr1->ai_next;
    }
    return false;
}
    

bool
__pam_rhostfilter_apply_list(
    const char          *list_file,
    struct addrinfo     *remote_addr,
    int                 *out_pam_result
)
{
    FILE                *list_file_ptr = fopen(list_file, "r");
    
    if ( list_file_ptr ) {
        char            *line = NULL;
        size_t          line_len = 0;
        int             pam_result = PAM_AUTH_ERR, pam_result_default = PAM_SUCCESS;
        struct addrinfo hints;
        bool            is_match_found = false;
        unsigned int    line_num = 0;
        
        // We don't need repeat records for different socket types, and
        // there's no flags or specific protocol necessary:
        memset(&hints, 0, sizeof(struct addrinfo));
            hints.ai_family = PAM_BYHOST_AI_FAMILY;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_flags = 0;
            hints.ai_protocol = 0;
            hints.ai_canonname = NULL;
            hints.ai_addr = NULL;
            hints.ai_next = NULL;
        
        while ( ! is_match_found && (getline(&line, &line_len, list_file_ptr) >= 0) && line ) {
            char    *line_ptr = line;
            
            line_num++;
            
            // Strip leading whitespace:
            while ( (*line_ptr != '\0') && isspace(*line_ptr) ) line_ptr++;
            
            // Is it an empty or comment line?
            if ( (*line_ptr == '\0') || (*line_ptr == '#') ) continue;
            
            // What command are we processing?
            if ( strncasecmp(line_ptr, "DEFAULT", 7) == 0 ) {
                int         pam_result_new;
                
                line_ptr += 7;
                
                // Drop leading whitespace:
                while ( (*line_ptr != '\0') && isspace(*line_ptr) ) line_ptr++;
                
                // Is it a word we're expecting?
                if ( strncasecmp(line_ptr, "ALLOW", 5) == 0 ) {
                    LOG("[INFO] Setting default disposition to Allow on line %u", line_num);
                    pam_result_new = PAM_SUCCESS;
                    line_ptr += 5;
                }
                else if ( strncasecmp(line_ptr, "DENY", 4) == 0 ) {
                    LOG("[INFO] Setting default disposition to Deny on line %u", line_num);
                    pam_result_new = PAM_PERM_DENIED;
                    line_ptr += 4;
                }
                else {
                    LOG("[ERR ] Ignored Default directive on line %u, invalid value: %s", line_num, line_ptr);
                    continue;
                }
                
                // Make sure the rest of the line is empty:
                while ( (*line_ptr != '\0') && isspace(*line_ptr) ) line_ptr++;
                if ( (*line_ptr == '\0') || (*line_ptr == '#') ) {
                    pam_result_default = pam_result_new;
                } else {
                    LOG("[ERR ] Invalid default disposition value on line %u (text remaining after value = %s)", line_num, line_ptr);
                }
            } else {
                int         match_pam_result;
                
                if ( strncasecmp(line_ptr, "ALLOW", 5) == 0 ) {
                    LOG("[INFO] Found Allow rule on line %u:", line_num);
                    match_pam_result = PAM_SUCCESS;
                    line_ptr += 5;
                }
                else if ( strncasecmp(line_ptr, "DENY", 4) == 0 ) {
                    LOG("[INFO] Found Deny rule on line %u:", line_num);
                    match_pam_result = PAM_PERM_DENIED;
                    line_ptr += 4;
                }
                else {
                    LOG("[ERR ] Invalid rule on line %u: %s", line_num, line_ptr);
                    continue;
                }
            
                // Loop over remaining words on the line:
                do {
                    // Skip leading whitespace:
                    while ( (*line_ptr != '\0') && isspace(*line_ptr) ) line_ptr++;
                
                    // Do we have something to look at?
                    if ( (*line_ptr != '\0') && (*line_ptr != '#') ) {
                        char            *word_start = line_ptr;
                        char            *word_end = line_ptr + 1;
                        char            *slash_ptr = NULL;
                        char            saved_char;
                        struct addrinfo *addr_results;
                        int             prefix_len = -1;
                    
                        // Find the end of the word (first whitespace or Nul):
                        while ( (*word_end != '\0') && ! isspace(*word_end) ) word_end++;
                    
                        // Nul-terminate the word for the time being; we'll restore
                        // the original character when we're done:
                        saved_char = *word_end;
                        *word_end = '\0';
                    
                        // Check for a "/" indicating a CIDR-type record; if found, then
                        // we'll Nul-terminate there, too:
                        if ( (slash_ptr = strrchr(word_start, '/')) ) {
                            char        *prefix_len_ptr = slash_ptr + 1;
                            int         nchar;
                            
                            *slash_ptr = '\0';
                            
                            // If we aren't able to convert to an integer, then we ignore
                            // the rest of the line:
                            if ( sscanf(prefix_len_ptr, "%d%n", &prefix_len, &nchar) != 1 ) continue;
                            if ( prefix_len < 0 || prefix_len > 128 ) {
                                LOG("[ERR ] Invalid prefix length of %d bits at line %u", prefix_len, line_num);
                                continue;
                            }
                            prefix_len_ptr += nchar;
                            
                            // Validate that we used the whole substring:
                            if ( *prefix_len_ptr != '\0' ) continue;
                        }
                        
                        if ( remote_addr ) {
                            // Get IP address(es) for the word:
                            if ( (getaddrinfo(word_start, NULL, &hints, &addr_results) == 0) && addr_results ) {
                                LOG("[ OK ]     %s", word_start);
                                if ( __pam_rhostfilter_addr_match(remote_addr, addr_results, prefix_len) ) {
#ifdef PAM_BYHOST_MODULE
                                    // A match!
                                    pam_result = match_pam_result;
                                    is_match_found = true;
#endif
                                }
                                freeaddrinfo(addr_results);
                            } else {
                                LOG("[FAIL]     %s (unable to resolve)", word_start);
                            }
                        }
                        
                        // Restore that terminal character after the word:
                        *word_end = saved_char;
                    
                        // Skip past this value:
                        line_ptr = word_end;
                    }
                } while ( ! is_match_found && (*line_ptr != '\0') && (*line_ptr != '#') );
            }
        }
        
        // Drop the line buffer:
        if ( line ) free((void*)line);
        
        // Close the file, we're all done:
        fclose(list_file_ptr);
        
        // Provide our result:
        *out_pam_result = (pam_result == PAM_AUTH_ERR) ? pam_result_default : pam_result;
        return true;
    } else {
        LOG("[ERR ] Failure to open filter list file `%s` (errno = %d) %s", list_file, errno, strerror(errno));
    }
    return false;
}


#ifdef PAM_BYHOST_MODULE


PAM_EXTERN int pam_sm_authenticate(pam_handle_t *handle, int flags, int argc, const char **argv){
    return PAM_SERVICE_ERR;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SERVICE_ERR;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SERVICE_ERR;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SERVICE_ERR;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv){
    return PAM_SERVICE_ERR;
}

PAM_EXTERN int
pam_sm_acct_mgmt(
    pam_handle_t        *pamh,	 
 	int                 flags,	 
 	int                 argc,	 
 	const char*         *argv
)
{
    int                 pam_result = PAM_AUTH_ERR;
    uid_t               local_uid;
    const char          *local_username = NULL;
    
    if ( (pam_get_item(pamh, PAM_USER, (const void**)&local_username) == PAM_SUCCESS) && local_username ) {
        struct passwd   *local_user = NULL;

        pam_syslog(pamh, LOG_DEBUG, "PAM_USER = %s", local_username);
#ifdef HAVE_PAM_MODUTIL
        local_user = pam_modutil_getpwnam(pamh, local_username);
#else
        local_user = getpwnam(local_username);
#endif
        if ( local_user ) {
            const char  *remote_host = NULL;
            
            pam_syslog(pamh, LOG_DEBUG, "PAM_USER_UID = %d", (int)local_user->pw_uid);
            
            if ( (pam_get_item(pamh, PAM_RHOST, (const void**)&remote_host) == PAM_SUCCESS) && remote_host ) {
                struct addrinfo     hints, *remote_addr;
                int                 argi;
                int                 noresolve_result = PAM_SUCCESS;
                int                 noconf_result = PAM_SUCCESS;
                
                pam_syslog(pamh, LOG_DEBUG, "PAM_RHOST = %s", remote_host);
                
                memset(&hints, 0, sizeof(struct addrinfo));
                    hints.ai_family = PAM_BYHOST_AI_FAMILY;
                    hints.ai_socktype = SOCK_STREAM;
                    hints.ai_flags = 0;
                    hints.ai_protocol = 0;
                    hints.ai_canonname = NULL;
                    hints.ai_addr = NULL;
                    hints.ai_next = NULL;
                
                // Check for any options passed to this module from the PAM config:
                argi = 0;
                while ( argi < argc ) {
                    const char  *arg = argv[argi++];
                    
                    if ( strncmp(arg, "noresolve=", 10) == 0 ) {
                        arg += 10;
                        if ( strcasecmp(arg, "deny") == 0 ) {
                            noresolve_result = PAM_PERM_DENIED;
                            pam_syslog(pamh, LOG_DEBUG, "  => DENY on unresolvable remove host");
                        }
                    }
                    else if (strncmp(arg, "noconf=", 7) == 0 ) {
                        arg += 7;
                        if ( strcasecmp(arg, "deny") == 0 ) {
                            noconf_result = PAM_PERM_DENIED;
                            pam_syslog(pamh, LOG_DEBUG, "  => DENY if local user has no " PAM_BYHOST_CONF_FILENAME);
                        }
                    }
                }
                    
                // Resolve to an address:
                if ( (getaddrinfo(remote_host, NULL, &hints, &remote_addr) == 0) && remote_addr ) {
                    const char      *conf_file = __pam_rhostfilter_default_conf_file(local_user->pw_uid);
                    struct stat     finfo;
                    
                    // Is the conf file present?
                    if ( __pam_rhostfilter_can_use_conf_file(conf_file, local_user->pw_uid) ) {
                        if ( __pam_rhostfilter_apply_list(conf_file, remote_addr, &pam_result) ) {
                            pam_syslog(pamh, LOG_DEBUG, "RESULT FOR %s FROM %s = %d", local_username, remote_host, pam_result);
                        } else {
                            // No config file:
                            pam_result = noconf_result;
                            pam_syslog(pamh, LOG_INFO, "No config file for user %s: %s", local_username, conf_file);
                        }
                    } else {
                        // No config file:
                        pam_result = noconf_result;
                        pam_syslog(pamh, LOG_INFO, "Invalid config file for user %s: %s", local_username, conf_file);
                    }
                    freeaddrinfo(remote_addr);
                } else {
                    // The remote hostname couldn't be resolved to an address:
                    pam_result = noresolve_result;
                    pam_syslog(pamh, LOG_WARNING, "Unable to resolve rhost `%s` to IP address", remote_host);
                }
            } else {
                // If there is no remote host, then we don't don't need to render an opinion:
                pam_result = PAM_SUCCESS;
                pam_syslog(pamh, LOG_DEBUG, "No remote host, byhost unnecessary for user %s", local_username);
            }
        } else {
            // The local user doesn't seem to have a passwd record?  That's
            // a major problem leading up to this point...
            pam_result = PAM_SERVICE_ERR;
            pam_syslog(pamh, LOG_ERR, "Unable to retrieve passwd record for authenticated user `%s`", local_username);
        }
    } else {
        // If there's no local user defined yet, then we cannot render an
        // opinion — which means a configuration error in our placement
        // in a config stack.   
        pam_result = PAM_AUTH_ERR;
        pam_syslog(pamh, LOG_ERR, "No mapped user provided to byhost pam_sm_acct_mgmt function");
    }
    return pam_result;
}

#else

#include <getopt.h>

static struct option check_opts[] = {
        { "help",       no_argument,            NULL, 'h' },
        { "conf",       required_argument,      NULL, 'c' },
        { "syntax",     no_argument,            NULL, 's' },
        { NULL,         0,                      NULL,  0  }
    };
const char *check_opts_str = "hc:s";

//

void
usage(
    const char  *exe
)
{
    printf(
            "usage:\n\n"
            "    %s {options> <hostname|ip-address> {<hostname|ip-address> ..}\n\n"
            "  options:\n\n"
            "    --help/-h                      show this information\n"
            "    --conf/-c <filename>           use this configuration file instead\n"
            "                                   of the default (%s)\n"
            "    --syntax/-s                    check file syntax only, no hostnames\n"
            "                                   or addresses necessary\n"
            "\n",
            exe,
            __pam_rhostfilter_default_conf_file(getuid())
        );  
}

//

int
main(
    int             argc,
    char * const    argv[]
)
{
    const char      *exe = argv[0];
    const char      *conf_file = NULL;
    bool            syntax_only = false;
    int             optch;
    struct stat     finfo;
    
    while ( (optch = getopt_long(argc, argv, check_opts_str, check_opts, NULL)) != -1 ) {
        switch ( optch ) {
        
            case 'h':
                usage(exe);
                exit(0);
            
            case 'c':
                conf_file = optarg;
                break;
                
            case 's':
                syntax_only = true;
                break;
        
        }
    }
    if ( ! conf_file ) {
        conf_file = __pam_rhostfilter_default_conf_file(getuid());
        if ( ! conf_file ) {
            fprintf(stderr, "FATAL ERROR:  unable to contruct default conf file name\n");
            exit(1);
        }
    }
    
    // Is the conf file present?  We can't check ownership, but all else:
    if ( ! __pam_rhostfilter_can_use_conf_file(conf_file, 0) ) {
        fprintf(stderr, "ERROR:  configuration file not acceptable: %s (errno = %d)\n", conf_file, errno);
        exit(errno);
    }
    
    // Skip past all options we consumed:
    argc -= optind;
    argv += optind;
    
    if ( syntax_only ) {
        int                 pam_result = PAM_AUTH_ERR;
        
        __pam_rhostfilter_apply_list(conf_file, NULL, &pam_result);
    }
    else if ( argc > 0 ) {
        struct addrinfo     *test_address;
        int                 pam_result;
        struct addrinfo     hints;
        int                 argi = 0;
        
        memset(&hints, 0, sizeof(struct addrinfo));
            hints.ai_family = PAM_BYHOST_AI_FAMILY;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_flags = 0;
            hints.ai_protocol = 0;
            hints.ai_canonname = NULL;
            hints.ai_addr = NULL;
            hints.ai_next = NULL;
        while ( argi < argc ) {
            if ( getaddrinfo(argv[argi], NULL, &hints, &test_address) == 0 ) {
                pam_result = PAM_AUTH_ERR;
                __pam_rhostfilter_apply_list(conf_file, test_address, &pam_result);
                freeaddrinfo(test_address);
            } else {
                fprintf(stderr, "ERROR:  unable to resolve `%s` to an IP address\n", argv[argi]);
            }
            argi++;
        }
    } else {
        fprintf(stderr, "ERROR:  no <hostname|ip-address> arguments provided\n");
        usage(exe);
        exit(EINVAL);
    }
    return 0;
}

#endif