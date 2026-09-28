#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>

#include <stdint.h>
#include <inttypes.h>
#include <math.h>

#define IPV4_MAX_LEN 15
#define PORT_MAX     9999

/*
 * Extract the first valid IPv4 address from 'input'.
 *
 * On success:
 *   ip_out   receives the IPv4 address, NUL terminated.
 *   outPort receives the port, or -1 if no port was present.
 *
 * Returns true on success, false if no valid IPv4 address was found.
 *
 * Examples accepted:
 *   "192.168.1.1"
 *   "server=192.168.1.1:8080"
 *   "IP: 10.0.0.1:443"
 *
 * Examples rejected:
 *   "192.168.01.1"       leading zero
 *   "192.168.1"          wrong octet count
 *   "192.168.1.256"      out of range
 *   "192.168..1.1"       empty octet
 *   "192.168.1.1:12345"  5-digit port
 *   "192.168.1.1::80"    second colon
 *   "192.168.1.1."      stray period
 *   "192.168.1.1:80:"   stray colon
 */
bool extractIPv4(const char *input, char *ip_out, int *outPort)
{
    if (!input || !ip_out || !outPort)
        return false;

    *outPort = -1;
    ip_out[0] = '\0';

    const char *p = input;

    while (*p) {
        /*
         * A candidate must begin with a digit.
         * This also prevents starting in the middle of an octet.
         */
        if (!isdigit((unsigned char)*p)) {
            p++;
            continue;
        }

        const char *start = p;
        unsigned int octets[4];
        int octet_count = 0;
        bool valid = true;

        /*
         * The character immediately before the candidate cannot be
         * a digit, '.' or ':'; otherwise this would be a partial
         * extraction from a larger malformed address.
         */
        if (start != input) {
            unsigned char prev = (unsigned char)start[-1];

            if (isdigit(prev) || prev == '.' || prev == ':') {
                p++;
                continue;
            }
        }

        while (octet_count < 4) {
            unsigned int value = 0;
            int digits = 0;

            /* Empty octet. */
            if (!isdigit((unsigned char)*p)) {
                valid = false;
                break;
            }

            /*
             * Leading zero is permitted only for the single digit "0".
             */
            if (*p == '0' && isdigit((unsigned char)p[1])) {
                valid = false;
                break;
            }

            while (isdigit((unsigned char)*p)) {
                /*
                 * More than three digits can never be a valid IPv4
                 * octet. Consume the candidate as invalid rather than
                 * accepting a shorter prefix.
                 */
                if (digits >= 3) {
                    valid = false;

                    while (isdigit((unsigned char)*p))
                        p++;

                    break;
                }

                value = value * 10u + (unsigned int)(*p - '0');
                digits++;
                p++;
            }

            if (!valid)
                break;

            if (value > 255 || digits == 0) {
                valid = false;
                break;
            }

            octets[octet_count++] = value;

            if (octet_count == 4)
                break;

            /*
             * Every separator between octets must be exactly one '.'.
             */
            if (*p != '.') {
                valid = false;
                break;
            }

            p++;

            /* Reject an empty octet such as "1.2.3..4". */
            if (!isdigit((unsigned char)*p)) {
                valid = false;
                break;
            }
        }

        /*
         * Must have exactly four octets.
         */
        if (!valid || octet_count != 4) {
            p = start + 1;
            continue;
        }

        /*
         * The character after the fourth octet determines what follows.
         *
         * '.' is forbidden because it would mean the address is part
         * of a larger dotted sequence.
         *
         * ':' is allowed only here, immediately after octet four.
         *
         * A digit is impossible here because the fourth-octet parser
         * consumed all consecutive digits.
         */
        const char *after_ip = p;

        if (*after_ip == '.') {
            p = start + 1;
            continue;
        }

        int port = -1;

        if (*after_ip == ':') {
            const char *port_start = after_ip + 1;
            const char *q = port_start;
            unsigned int port_value = 0;
            int port_digits = 0;

            /*
             * Port must contain at least one digit.
             */
            if (!isdigit((unsigned char)*q)) {
                p = start + 1;
                continue;
            }

            /*
             * Parse the port. Five or more digits invalidate the
             * entire candidate, rather than accepting its first four.
             */
            while (isdigit((unsigned char)*q)) {
                if (port_digits >= 4) {
                    valid = false;

                    /*
                     * Consume the entire digit sequence so a 5-digit
                     * port cannot accidentally be partially re-matched.
                     */
                    while (isdigit((unsigned char)*q))
                        q++;

                    break;
                }

                /*
                 * Disallow leading zeros in multi-digit ports.
                 */
                if (port_digits == 0 && *q == '0' &&
                    isdigit((unsigned char)q[1])) {
                    valid = false;

                    while (isdigit((unsigned char)*q))
                        q++;

                    break;
                }

                port_value = port_value * 10u +
                             (unsigned int)(*q - '0');

                port_digits++;
                q++;
            }

            if (!valid) {
                p = start + 1;
                continue;
            }

            /*
             * Port range: 1..9999.
             */
            if (port_digits == 0 || port_value == 0 ||
                port_value > PORT_MAX) {
                p = start + 1;
                continue;
            }

            /*
             * A second colon immediately following the port is
             * explicitly forbidden.
             */
            if (*q == ':') {
                p = start + 1;
                continue;
            }

            /*
             * A period immediately following the port is also
             * considered a stray delimiter.
             */
            if (*q == '.') {
                p = start + 1;
                continue;
            }

            port = (int)port_value;
            after_ip = q;
        }

        /*
         * If the address had no port, a colon here would have been
         * handled above. Any '.' was already rejected.
         *
         * Also prevent extraction from something such as:
         *   192.168.1.1:80:90
         *   192.168.1.1.5
         */
        if (*after_ip == ':' || *after_ip == '.') {
            p = start + 1;
            continue;
        }

        /*
         * Copy the validated IPv4 address.
         */
        size_t ip_len = (size_t)(p - start);

        if (ip_len >= 16) {
            ip_out[0] = '\0';
            return 0;
        }

        memcpy(ip_out, start, ip_len);
        ip_out[ip_len] = '\0';

        *outPort = port;
        return 1;
    }
    ip_out[0] = '\0';
    return 0;
}

unsigned long octaveConversion(char IP[16]) {
    int nums[4] = {0};
    // printf("%s", IP);
    char *portion = strtok(IP, ".");
    int i = 0;
    while (portion != NULL) {
        for (int j = 0; j < strlen(portion); j++) { nums[i] += (portion[j] - '0') * pow(10, strlen(portion)-(j+1)); } //printf("+ %d * 10 TO THE POWER OF %d\n", (portion[j] - '0'), strlen(portion)-(j+1)); }
        i++;
        //printf("%s\n", portion);
        portion = strtok(NULL, ".");
    }
    //printf("%d\n", nums[0]); printf("%d\n", nums[1]); printf("%d\n", nums[2]); printf("%d\n", nums[3]);
    unsigned long literalVal = ((unsigned long)nums[0] << 24) | ((unsigned long)nums[1] << 16) | ((unsigned long)nums[2] << 8) | (unsigned long)nums[3];
    return literalVal;
}

int main(void)
{

    char userInput[100];
    char IP[16];
    int PORTNUM;

    while (1) {

        printf("Enter a string (or 'END' to quit): ");
        fgets(userInput, 100, stdin);

        if (strncmp(userInput, "END", 3) == 0)
        {
            printf("Program terminated.\n");
            break;
        }
        else {
            if (extractIPv4(userInput, IP, &PORTNUM) == 1) {
                printf("Extracted IPv4 address: %s (decimal value: ", IP);
                if (PORTNUM >= 0)
                    printf("%lu, port: %d)\n", octaveConversion(IP), PORTNUM);
                else
                    printf("%lu, port: none)\n", octaveConversion(IP));
            } else { printf("Invalid input: no valid IPv4 address found\n"); }
        }
    }

    return 0;
}

// One interpretation worth making explicit: this implementation treats 0 as a valid octet, but rejects 00, 01, etc.; for ports it allows 1–9999 and likewise rejects leading-zero forms such as 080.
