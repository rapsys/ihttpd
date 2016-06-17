/**
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Written by Raphaël Gertz <rapsys@rapsys.eu>
 */

//Required for mkostemp, O_CLOEXEC, strdup, memmem
#define _GNU_SOURCE

//Required for SSIZE_MAX, LONG_MAX
#include <limits.h>

//Required for pid_t, kill, waitpid
#include <sys/wait.h>
#include <signal.h>

//Required for printf, sscanf, sprintf
#include <stdio.h>

//Required for struct stat, fstat
#include <sys/stat.h>

//Required for closedir, DIR, opendir, readdir, struct dirent
#include <dirent.h>

//Required for close, dup2, execve, fork, read, STDERR_FILENO, STDOUT_FILENO, STDIN_FILENO, write
#include <unistd.h>

//Required for open, O_CLOEXEC, O_NOATIME, O_NOFOLLOW
#include <fcntl.h>

//Required for atoi, calloc, exit, EXIT_FAILURE, EXIT_SUCCESS, free, getenv, malloc, realloc
#include <stdlib.h>

//Required for memchr, memcpy, memmem, strdup, strlen, strncmp
#include <string.h>

//Required for bool
#include <stdbool.h>

//Required for nanosleep
#include <time.h>

//Default passphrase max size
#define DEFAULT_PASSPHRASE_SIZE_MAX 512

//Default keyfile max size
//XXX: file should be maximum 8192*1024-1 character long
#define DEFAULT_KEYFILE_SIZE_MAX (8192 * 1024)

//Default crypttab
#define CRYPTTAB "/etc/crypttab"

//Default cryptsetup
#define CRYPTSETUP "/sbin/cryptsetup"

//Default pid file
#define IHTTPDPID "/run/ihttpd/ihttpd.pid"

//Default systemd ask-password dir
#define ASKPASSWORDDIR "/run/systemd/ask-password"

//Define child log
#define ASKPASSWORDLOG "/run/ihttpd/log/child.askpassword.log"
#define IHTTPDLOG "/run/ihttpd/log/child.ihttpd.log"

//Create struct for http error status
struct httpStatusStruct {
	int value;
	char *description;
};

//Declare http error status array
const struct httpStatusStruct httpStatuses[] = {
	{200, "OK"},
	{400, "Bad Request"},
	{405, "Method Not Allowed"},
	{411, "Length Required"},
	{500, "Internal Server Error"}
};

/**
 * Prototype
 */
void die(const int, const char*);
void header(const int, const char*);
void showForm(const char*, const int, const int);
int extractValue(char**, int*, char*, int);
int extractLuksDevice(char**, char**);
int extractIHttpdPid(pid_t *);
int extractAskPasswordPid(pid_t *);

/**
 * Die with error
 */
void die(const int code, const char *err) {
	//TODO: see if we add a nice text/html template ?
	//Send content as text
	header(code, "text/plain");
	//Print error line if available
	if (err != NULL)
		printf("%s", err);
	//Flush all
	if (fflush(NULL) == -1) {
		perror("fflush");
	}
	//Exit with failure code
	exit(EXIT_FAILURE);
}

/**
 * Send header
 */
void header(const int code, const char *ctype) {
	int k;
	switch(code) {
		case 400:
			k = 1;
			break;
		case 405:
			k = 2;
			break;
		case 411:
			k = 3;
			break;
		case 500:
			k = 4;
			break;
		default:
			k = 0;
	}
	//Send http status
	printf("Status: %d %s\r\n", httpStatuses[k].value, httpStatuses[k].description);
	//Make sure no cache
	printf("Cache-Control: no-cache, no-store, must-revalidate\r\n");
	printf("Pragma: no-cache\r\n");
	printf("Expires: 0\r\n");
	printf("X-Robots-Tag: noindex, nofollow, noarchive, nosnippet, noodp\r\n");
	printf("Content-type: %s\r\n\r\n", ctype);
}

/**
 * Show form
 */
void showForm(const char *requestUri, const int keyfileSizeMax, const int passphraseSizeMax) {
	header(200, "text/html");
	printf("<!DOCTYPE HTML>\r\n");
	printf("<html>\r\n");
	printf("<head><title>Key upload form</title></head>\r\n");
	printf("<body>\r\n");
	printf("<div id=\"wrapper\">\r\n");
	printf("<form enctype=\"multipart/form-data\" action=\"%s\" method=\"post\"><fieldset><legend>Upload key</legend><label for=\"file\"></label><input type=\"hidden\" name=\"MAX_FILE_SIZE\" value=\"%d\" /><input id=\"file\" type=\"file\" name=\"key\" /><input type=\"submit\" value=\"Send\" /></fieldset></form>\r\n", requestUri, keyfileSizeMax);
	printf("<form action=\"%s\" method=\"post\"><fieldset><legend>Type key</legend><label for=\"password\"></label><input id=\"password\" type=\"password\" name=\"key\" maxlength=\"%d\" /><input type=\"submit\" value=\"Send\" /></fieldset></form>\r\n", requestUri, passphraseSizeMax);
	printf("</div>\r\n");
	printf("</body>\r\n");
	printf("</html>\r\n");
}

/**
 * Extract value
 */
int extractValue(char **value, int *valueLength, char *contentType, int contentLength) {
	//Handle application/x-www-form-urlencoded request
	if (contentType != NULL && !strncmp(contentType, "application/x-www-form-urlencoded", 33)) {
		//Indexes and return
		int i, k, v, r;
		//Declare key and buf
		char *key, *buf;
		//Allocate key
		if ((key = malloc(4*sizeof(char))) == NULL) {
			//Unable to allocate key
			return -1;
		}
		//Allocate buf to maximum possible value size + 1 for trailing \0
		if ((buf = calloc(1, (DEFAULT_PASSPHRASE_SIZE_MAX+1)*sizeof(char))) == NULL) {
			//Unable to allocate value
			free(key);
			return -2;
		}
		//Char buffer
		char d = '\0';
		//Char delimiter
		//XXX: initialised as & for new key, becomes = when fetching value
		char delim = '&';
		for (i = 0, k = 0, v = 0; i < contentLength; i++) {
			//Safeguard against a value greater than DEFAULT_PASSPHRASE_SIZE_MAX
			//XXX: this should never happen because we should be protected by contentLength already
			if (v == DEFAULT_PASSPHRASE_SIZE_MAX+1) {
				//Invalid value
				free(key);
				free(buf);
				return -3;
			}
			//Read one character from stdin
			r = read(STDIN_FILENO, &d, 1);
			//Handle errors
			if (r < 0) {
				//Error while parsing post data
				free(key);
				free(buf);
				return -4;
			} else if (r == 0) {
				//Partial receive
				free(key);
				free(buf);
				return -5;
			}
			//Handle case where key has an other name
			if (i == 3) {
				//Check key is "key" and we get '=' as new char and assign delim to =
				if (strncmp(key, "key", 3) || (delim = d) != '=') {
					//Invalid key
					free(key);
					free(buf);
					return -6;
				}
			//Handle key or value separator in query string
			} else if (d == '&' || d == '=') {
				//Invalid query string
				free(key);
				free(buf);
				return -7;
			//Handle a value
			} else {
				//Save key char
				if (delim == '&') {
					key[k] = d;
					k++;
				//Save buf char
				} else {
					buf[v] = d;
					v++;
				}
			}
		}
		//Free key
		free(key);
		//Unescape and reduce value if not empty
		if (v > 0) {
			//Declare iterators
			int l,m, s = v;
			//Loop on value and reduce length on the fly
			for(l=0,m=0; m < v; l++,m++) {
				//Replace + with space
				if (buf[m] == '+') {
					buf[l] = ' ';
				//Skip partial present %XX
				} else if (
					//Assign char
					(buf[l] = buf[m]) == '%' &&
					//Check we didn't reach valueStrLength
					(m+2 < v) &&
					//Check next two digits are valid
					((buf[m+1] >= 'A' && buf[m+1] <= 'F') || (buf[m+1] >= 'a' && buf[m+1] <= 'f') || (buf[m+1] >= '0' && buf[m+1] <= '9')) &&
					((buf[m+2] >= 'A' && buf[m+2] <= 'F') || (buf[m+2] >= 'a' && buf[m+2] <= 'f') || (buf[m+2] >= '0' && buf[m+2] <= '9'))
				) {
					buf[l] = (buf[m+1] >= 'A' ? (buf[m+1] & 0xdf) - 'A' + 10 : buf[m+1] - '0') * 16 + (buf[m+2] >= 'A' ? (buf[m+2] & 0xdf) - 'A' + 10 : buf[m+2] - '0');
					m += 2;
					s -= 2;
				}
			}
			//Set value length
			*valueLength = s;
			//Alloc value
			if ((*value = malloc((*valueLength)*sizeof(char))) == NULL) {
				//Unable to alloc value
				free(key);
				free(buf);
				return -8;
			}
			//Copy value
			memcpy(*value, buf, *valueLength);
		}
		//Free buf
		free(buf);
	//Handle multipart/form-data request
	} else if (contentType != NULL && !strncmp(contentType, "multipart/form-data", 19)) {
		//Indexes and return
		int b, s, r;
		//Boundary length
		int boundaryLength = strlen(contentType) - 30 + 1;
		//Client send LF ending without CR
		int lfstyle = 0;
		//Declare boundary
		char *boundary;
		//Allocate boundary
		if ((boundary = calloc(1, boundaryLength*sizeof(char))) == NULL) {
			//Unable to allocate boundary
			return -9;
		}
		//Extract boundary
		memcpy(boundary, contentType + 30, boundaryLength - 1);

		//Declare buffers
		char *start, *buf;
		//Allocate buffer
		if ((buf = malloc(contentLength*sizeof(char))) == NULL) {
			//Unable to allocate buffer
			free(boundary);
			return -10;
		}
		//Char buffer
		char d = '\0';

		//Loop
		for (b = 0, s = 0; b < contentLength; b++) {
			//Detect possible boundary
			//XXX: b is boundaryLength-1 + 2 after s
			//XXX: d will be a CR(CRLF line ending) or LF(LF line ending) or -(of final --)
			if (b == s + 2 + boundaryLength - 1 && !strncmp(boundary, buf + b - boundaryLength + 1, boundaryLength - 1)) {
				//Only after first boundary match
				if (s > 0) {
					//Trim line jump
					if (start[0] == '\r' && start[1] == '\n') {
						start += 2;
						lfstyle = 1;
					} else if (start[0] == '\n') {
						start++;
					}
					//Found flag
					bool found = false;
					//Allocate pointers
					char *new = start, *prev = start, *name = NULL;
					//Search for a new line
					while ((new = memchr(new, '\n', b - (new - buf)))) {
						//Jump to first character after new line
						new++;
						//Init line length
						int lineLength = new - prev - 1;
						//Remove chariage return if necessary
						if (prev[lineLength] == '\r') {
							lineLength--;
							lfstyle = 1;
						}
						//Break loop after headers end
						if (lineLength == 1) {
							break;
						}
						//Allocate a name buf of maximum line length
						//XXX: need to be filled with zero as we don't know what will comes with sscanf call and we rely on strlen
						if ((name = calloc(1, lineLength*sizeof(char))) == NULL) {
							//Unable to allocate name
							free(boundary);
							free(buf);
							return -11;
						}
						//Search for name
						if (sscanf(prev, "Content-Disposition: form-data; name=\"%[^\"]\"", name)) {
							//Realloc name
							if ((name = realloc(name, (strlen(name)+1)*sizeof(char))) == NULL) {
								//Unable to reduce name
								free(boundary);
								free(buf);
								free(name);
								return -12;
							}
							if (!strncmp(name, "key", 3)) {
								found = true;
							}
						}
						//Free name
						free(name);
						//Jump to next one
						prev = new;
					}
					//Init value if found
					if (found) {
						//Declare end
						char *end = buf + b - boundaryLength - 3;
						//Remove CR at end if provided
						//XXX: only remove CR at end if we encountered one before
						if (lfstyle) {
							end++;
						}
						//On too big keyfile
						if (end - new - 1 >= DEFAULT_KEYFILE_SIZE_MAX) {
							//Keyfile too large
							free(boundary);
							free(buf);
							return -13;
						}
						//On non empty value
						if (end - new > 1) {
							//Set value length
							*valueLength = end - new - 1;
							//Allocate value
							if ((*value = malloc((*valueLength)*sizeof(char))) == NULL) {
								//Unable to allocate value
								free(boundary);
								free(buf);
								return -14;
							}
							//Copy value
							memcpy(*value, new, *valueLength);
						}
					}
				}
				//Set start to matched boundary
				start = buf + b;
			}
			//Read one character from stdin
			r = read(STDIN_FILENO, &d, 1);
			//Handle errors
			if (r < 0) {
				//Error while parsing post data
				free(boundary);
				free(buf);
				return -15;
			} else if (r == 0) {
				//Partial receive
				free(boundary);
				free(buf);
				return -16;
			}
			//New line case
			if (d == '\n') {
				//Store new possible boundary start
				s = b + 1;
			}
			buf[b] = d;
		}

		//Free buffers
		free(boundary);
		free(buf);
	//Unhandled request
	} else {
		return -17;
	}

	//Send value
	return 0;
}

/**
 * Extract luks and device
 */
int extractLuksDevice(char **luks, char **device) {
	//Declare file descriptor
	int fd, bufLength;
	//Declare buf, device and luks pointer
	char *buf, *d, *l;
	//Declare stat struct
	struct stat *stats;
	//Open file
	if ((fd = open(CRYPTTAB, O_RDONLY|O_NOATIME|O_NOFOLLOW|O_CLOEXEC)) == -1) {
		//Can't open crypttab file
		return -1;
	}
	//Allocate stats
	if ((stats = calloc(1, sizeof(struct stat))) == NULL) {
		//Unable to allocate stats
		return -2;
	}
	//Stat file
	if (fstat(fd, stats) == -1) {
		//Can't stat crypttab
		return -3;
	}
	//Check file size
	if ((bufLength = stats->st_size) > SSIZE_MAX) {
		//Crypttab too big
		return -4;
	}
	//Allocate buf
	if ((buf = malloc(bufLength*sizeof(char))) == NULL) {
		//Unable to allocate buf
		return -5;
	}
	//Read file
	if ((read(fd, buf, bufLength)) < bufLength) {
		//Fail to read crypttab file
		return -6;
	}
	//Close file
	close(fd);
	//Free stats buffer
	free(stats);

	//Search first separator (\s|\t) after luks
	if ((l = memchr(buf, ' ', bufLength)) == NULL && (l = memchr(buf, '	', bufLength)) == NULL) {
		return -7;
	}
	//Jump to next char
	l++;
	//Search first separator (\s|\t) after device
	if ((d = memchr(l, ' ', bufLength - (l - buf))) == NULL && (d = memchr(l, '	', bufLength - (l - buf))) == NULL && (d = memchr(l, '\n', bufLength - (l - buf))) == NULL) {
		return -8;
	}
	//Jump to next char
	d++;

	//Alloc luks
	if ((*luks = malloc((l - buf - 1)*sizeof(char))) == NULL) {
		return -9;
	}
	//Allocate device
	if ((*device = malloc((d  - l - 1)*sizeof(char))) == NULL) {
		//Free and reset luks
		free(luks);
		luks=NULL;
		return -10;
	}

	//Copy luks
	memcpy(*luks, buf, l  - buf - 1);
	//Terminate luks
	(*luks)[l - buf - 1] = '\0';

	//Copy device
	memcpy(*device, l, d  - l - 1);
	//Terminate device
	(*device)[d - l - 1] = '\0';

	//Free buffer
	free(buf);

	//Success
	return 0;
}

/**
 * Extract ask-password pid
 */
int extractAskPasswordPid(pid_t *pid) {
	//Declare stuct dirent
	struct dirent *entry;
	//Declare askdir
	DIR *askdir;
	//Declare found
	int found = 0;

	//Allocate dirent struct
	if ((entry = calloc(1, sizeof(struct dirent))) == NULL) {
		//Unable to allocate entry
		return -1;
	}

	//Open systemd ask-password dir
	if ((askdir = opendir(ASKPASSWORDDIR)) == NULL) {
		//Can't open ask dir
		return -2;
	}

	//Change dir
	if (chdir(ASKPASSWORDDIR) == -1) {
		//Can't change to ask dir
		return -3;
	}

	//Loop on dir content
	while((entry = readdir(askdir))) {
		//Handle each ask.XXXXXX file
		if (!strncmp(entry->d_name, "ask.", 4) && strlen(entry->d_name) == 10) {
			//Declare file descriptor
			int fd, bufLength;
			//Declare buf
			char *buf;
			//Declare stat struct
			struct stat *stats;
			//Open file
			if ((fd = open(entry->d_name, O_RDONLY|O_NOATIME|O_NOFOLLOW|O_CLOEXEC)) == -1) {
				//Can't open ask file
				return -4;
			}
			//Allocate stats
			if ((stats = calloc(1, sizeof(struct stat))) == NULL) {
				//Unable to allocate stats
				return -5;
			}
			//Stat file
			if (fstat(fd, stats) == -1) {
				//Can't stat ask file
				return -6;
			}
			//Check file size
			if ((bufLength = stats->st_size) > SSIZE_MAX) {
				//Ask file too big
				return -7;
			}
			//Allocate buf
			if ((buf = malloc(bufLength*sizeof(char))) == NULL) {
				//Unable to allocate buf
				return -8;
			}
			//Read file
			if ((read(fd, buf, bufLength)) < bufLength) {
				//Fail to read ask file
				return -9;
			}
			//Close file
			close(fd);
			//Free stats buffer
			free(stats);

			//Allocate pointers
			char *nl = buf, *pl = buf, *e;
			//Allocate pid
			*pid = 0;

			//Search for a new line
			while ((nl = memmem(nl, bufLength - (nl - buf), "\n", strlen("\n")))) {
				//Jump to next char
				nl++;

				//Check if we have a = in line but not empty value ("=\n")
				if ((e = memmem(pl, bufLength - (pl - buf), "=", strlen("="))) && e < nl - 2) {
					//Jump to next char
					e++;
					//Look for PID
					if (!strncmp(pl, "PID", 3)) {
						//Declade pid string
						char *pidStr;
						//Allocate pid string
						if ((pidStr = malloc((nl - e)*sizeof(char))) == NULL) {
							//Unable to allocate pid string
							return -10;
						}
						//Copy pid
						memcpy(pidStr, e, nl - e - 1);
						//Terminate pid string
						pidStr[nl - e] = '\0';
						//Check pid value
						if ((*pid = atoi(pidStr)) <= 1) {
							//Invalid pid
							return -11;
						}
						//Free pid string
						free(pidStr);
						//Found a valid process
						found++;
					}
				}

				//Jump prev line to new line
				pl = nl;
			}

			//Free buffers
			free(buf);
		}
	}

	//Close systemd ask-password dir
	if (closedir(askdir) == -1) {
		//Can't close ask dir
		return -13;
	}

	//Free entry
	free(entry);

	//Found no valid pid
	if (found == 0) {
		//No pid found
		return -14;
	//Found more than one pid
	} else if (found > 1) {
		//No pid found
		return -15;
	}

	//Success
	return 0;
}

/**
 * Extract ihttpd pid
 */
int extractIHttpdPid(pid_t *pid) {
	//Declare file descriptor
	int fd, bufLength;
	//Declare buf, device and luks pointer
	char *buf, *l, *pidStr;
	//Declare stat struct
	struct stat *stats;
	//Open file
	if ((fd = open(IHTTPDPID, O_RDONLY|O_NOATIME|O_NOFOLLOW|O_CLOEXEC)) == -1) {
		//Can't open crypttab file
		return -1;
	}
	//Allocate stats
	if ((stats = calloc(1, sizeof(struct stat))) == NULL) {
		//Unable to allocate stats
		return -2;
	}
	//Stat file
	if (fstat(fd, stats) == -1) {
		//Can't stat crypttab
		return -3;
	}
	//Check file size
	if ((bufLength = stats->st_size) > SSIZE_MAX) {
		//Crypttab too big
		return -4;
	}
	//Allocate buf
	if ((buf = malloc(bufLength*sizeof(char))) == NULL) {
		//Unable to allocate buf
		return -5;
	}
	//Read file
	if ((read(fd, buf, bufLength)) < bufLength) {
		//Fail to read crypttab file
		return -6;
	}
	//Close file
	close(fd);
	//Free stats buffer
	free(stats);

	//Search first separator (\s|\t|\n) after pid
	if ((l = memchr(buf, ' ', bufLength)) == NULL && (l = memchr(buf, '	', bufLength)) == NULL && (l = memchr(buf, '\n', bufLength)) == NULL) {
		return -7;
	}
	//Jump to next char
	l++;

	//Alloc pid string
	if ((pidStr = malloc((l - buf - 1)*sizeof(char))) == NULL) {
		return -9;
	}

	//Copy luks
	memcpy(pidStr, buf, l  - buf - 1);
	//Terminate luks
	pidStr[l - buf - 1] = '\0';

	//Free buffer
	free(buf);

	//Store pid
	if ((*pid = atoi(pidStr)) <= 1) {
		//Invalid pid
		return -10;
	}

	//Free pid string
	free(pidStr);

	//Success
	return 0;
}

/**
 * Main function
 */
int main(int argc, char **argv) {

	//Get request method
	char *requestMethod = getenv("REQUEST_METHOD");

	//Handle unknown requests
	if (requestMethod == NULL || (strncmp(requestMethod, "GET", 3) && strncmp(requestMethod, "HEAD", 4) && strncmp(requestMethod, "POST", 4))) {
		//Send method not allowed
		die(405, "Unsupported request method");
	//Handle get and head
	} else if (!strncmp(requestMethod, "GET", 3) || !strncmp(requestMethod, "HEAD", 4)) {
		//Send form
		showForm(getenv("REQUEST_URI")?getenv("REQUEST_URI"):"/", DEFAULT_KEYFILE_SIZE_MAX, DEFAULT_PASSPHRASE_SIZE_MAX);
	//Handle post
	} else /*if (!strncmp(requestMethod, "POST", 4))*/ {
		//Return value
		int ret;

		//Child pid
		pid_t pid;

		//Value length
		//XXX: will contain number of char in value without trailing \0
		int valueLength;
		//Value string
		//XXX: will contain value without a tailing \0
		char *value = NULL;

		//Content length
		int contentLength;
		//Content length string from env
		char *contentLengthStr = getenv("CONTENT_LENGTH");
		//Content type
		char *contentType = getenv("CONTENT_TYPE");

		//Declare luks and device
		char *luks = NULL, *device = NULL;

		//Pairs of pipe for stdin, stdout and stderr
		int inPipe[2], errPipe[2];

		//Handle unknown content type
		if (contentType == NULL || (strncmp(contentType, "application/x-www-form-urlencoded", 33) && strncmp(contentType, "multipart/form-data", 19))) {
			die(400, "Unknown content type");
		}

		//Handle invalid multipart/form-data content type
		//XXX: max boundary length is 70 as per rfc1521 & rfc2046
		if (!strncmp(contentType, "multipart/form-data", 19) && (strncmp(contentType, "multipart/form-data; boundary=", 30) || strlen(contentType) <= 30 || strlen(contentType) > 100)) {
			die(400, "Malformed boundary in multipart/form-data request");
		}

		//Handle invalid content length
		//XXX: deny empty contentLength as chrome send a contentLength even for a device
		if (contentLengthStr == NULL || (contentLength = atoi(contentLengthStr)) <= 0) {
			die(411, "Invalid content length");
		}

		//Handle application/x-www-form-urlencoded request length
		//XXX: limit to key=xyz where xyz can be all encoded in %XX
		if (!strncmp(contentType, "application/x-www-form-urlencoded", 33) && contentLength > (DEFAULT_PASSPHRASE_SIZE_MAX * 3 + 4)) {
			die(400, "Invalid application/x-www-form-urlencoded request length");
		}

		//Handle multipart/form-data request length
		//XXX: limit to arbitrary 3 times the keyfile max size
		if (!strncmp(contentType, "multipart/form-data", 19) && contentLength > (DEFAULT_KEYFILE_SIZE_MAX * 3)) {
			die(400, "Invalid multipart/form-data request length");
		}

		//Extract value
		if ((ret = extractValue(&value, &valueLength, contentType, contentLength)) < 0) {
			die(500, "Failed to extract value");
		}


		//Extract luks and device
		if ((ret = extractLuksDevice(&luks, &device)) < 0) {
			die(500, "Failed to extract luks and device");
		}

		//Create stdin pipe
		if (pipe(inPipe) == -1) {
			die(500, "Failed to create in pipe");
		}

		//Create stderr pipe
		if (pipe(errPipe) == -1) {
			die(500, "Failed to create err pipe");
		}

		//Fork process
		if ((pid = fork()) == -1) {
			die(500, "Failed to fork");
		}

		//Child process
		if (pid == 0) {
			//Child argv
			char *cargv[] = { CRYPTSETUP, "-d", "-", "luksOpen", device, luks, NULL };
			char *carge[] = { NULL };
			//Free value
			free(value);
			//Redirect stdin to pipe
			if (dup2(inPipe[0], STDIN_FILENO) == -1) {
				die(500, "Failed to redirect in pipe");
			}
			//Close inPipe
			close(inPipe[0]);
			close(inPipe[1]);
			//Redirect stderr to pipe
			if (dup2(errPipe[1], STDERR_FILENO) == -1) {
				die(500, "Failed to redirect err pipe");
			}
			//Close errPipe
			close(errPipe[0]);
			close(errPipe[1]);
			//Call cryptsetup
			if (execve(CRYPTSETUP, cargv, carge) == -1) {
				die(500, "Failed to call cryptsetup");
			}
		//Parent process
		} else {
			//Free luks
			free(luks);
			//Free device
			free(device);

			//Close unused inPipe end
			close(inPipe[0]);
			//Close unused errPipe end
			close(errPipe[1]);

			//Send password on stdin anyway
			//XXX: this fail if device is already unlocked for example
			write(inPipe[1], value, valueLength);

			//Free value
			free(value);

			//Close stdin with EOF
			close(inPipe[1]);

			//Wait child
			if (waitpid(pid, &ret, 0) == -1) {
				die(500, "Failed to wait child");
			}

			//Handle already unlocked device
			if (ret == 1280) {
				die(200, "Device already unlocked");
			//Handle already in use device
			} else if (ret == 5) {
				die(500, "Device already in use");
			//Handle invalid luks device
			} else if (ret == 256) {
				die(500, "Device is now a valid device");
			//Handle no key available with this passphrase
			} else if (ret == 512) {
				die(500, "No slot for this value");
			//Handle unexisting device or permission denied
			} else if (ret == 1014) {
				die(500, "Device doesn't exist or access denied");
			//Unknown error
			} else if (ret != 0) {
				//Err length and counter
				int errLength = 2048, e = 0;
				//Declare err buffer
				char *err;
				//Buffer char
				char c;
				//Alloc err buffer
				if ((err = malloc(errLength*sizeof(char))) == NULL) {
					die(500, "Couldn't alloc err buffer");
				}
				//Advance after ret code
				e = sprintf(err, "%d:", ret);
				//Fetch stderr and store in err buffer
				while(read(errPipe[0], &c, 1) > 0) {
					//Grow buffer if we reach end
					if (e == errLength) {
						if ((err = realloc(err, (errLength+2048)*sizeof(char))) == NULL) {
							die(500, "Couldn't grow err buffer");
						}
						errLength += 2048;
					}
					//Store character
					err[e] = c;
					//Pass to next
					e++;
				}
				//Terminate err buffer
				err[e] = '\0';
				//Realloc err buffer
				if ((err = realloc(err, (e+1)*sizeof(char))) == NULL) {
					die(500, "Couldn't ungrow err buffer");
				}
				//Die with luks error
				die(500, err);
			}
			//Close errPipe
			close(errPipe[0]);
		}

		//Fork process
		if ((pid = fork()) == -1) {
			die(500, "Failed to fork");
		}

		//IHttpd killing child process
		if (pid == 0) {
			//File descriptor
			int fd;

			//Declare ihttpd pid
			pid_t ihttpdPid;

			//Close stdin
			close(STDIN_FILENO);

			//Disable line buffering on stdout and stderr
			setvbuf(stdout, NULL, _IONBF, 0);
			setvbuf(stderr, NULL, _IONBF, 0);

			//Redirect output to log
			if ((fd = open(IHTTPDLOG, O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR)) == -1) {
				fprintf(stderr, "Open ihttpd child log failed\n");
			} else {
				//Close stdout
				close(STDOUT_FILENO);
				//Redirect stdout on childlog
				if (dup2(fd, STDOUT_FILENO) == -1) {
					fprintf(stderr, "Redirect stdout to ihttpd child log failed\n");
				}
				//Close stderr
				close(STDERR_FILENO);
				//Redirect stderr on childlog
				if (dup2(fd, STDERR_FILENO) == -1) {
					fprintf(stderr, "Redirect stderr to ihttpd child log failed\n");
				}
				//Close childlog fd
				close(fd);
			}

			//Extract ihttpd pid
			if (extractIHttpdPid(&ihttpdPid) < 0) {
				fprintf(stderr, "Failed to extract ihttpd pid");
				exit(EXIT_FAILURE);
			}

			//Close stdout and stderr without childlog
			if (fd == -1) {
				close(STDOUT_FILENO);
				close(STDERR_FILENO);
			}

			//Wait until get rattached to init(getppid()==1)
			//XXX: we are really blind here
			while(getppid() != 1) {
				//Sleep half a second
				if (usleep(500000) == -1 && fd != -1) {
					printf("Usleep failed\n");
				}
			}

			//Termiate ihttpd
			if (kill(ihttpdPid, 0) == 0 && kill(ihttpdPid, SIGTERM) == -1 && fd != -1) {
				printf("Termiate ihttpd failed\n");
			}

			//Sleep half a second
			if (usleep(500000) == -1 && fd != -1) {
				printf("Usleep failed\n");
			}

			//Kill ihttpd
			if (kill(ihttpdPid, 0) == 0 && kill(ihttpdPid, SIGKILL) == -1) {
				printf("Kill ihttpd failed\n");
			}

		//Parent process
		} else {

			//Fork process
			if ((pid = fork()) == -1) {
				die(500, "Failed to fork");
			}

			//Ask password killing child process
			//XXX: we are blind here
			if (pid == 0) {
				//File descriptor
				int fd;

				//Declare ask password pid
				pid_t askPasswordPid;

				//Close stdin
				close(STDIN_FILENO);

				//Disable line buffering on stdout and stderr
				setvbuf(stdout, NULL, _IONBF, 0);
				setvbuf(stderr, NULL, _IONBF, 0);

				//Redirect output to log
				if ((fd = open(ASKPASSWORDLOG, O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR)) == -1) {
					fprintf(stderr, "Open ask password child log failed\n");
				} else {
					//Close stdout
					close(STDOUT_FILENO);
					//Redirect stdout on childlog
					if (dup2(fd, STDOUT_FILENO) == -1) {
						fprintf(stderr, "Redirect stdout to ask password child log failed\n");
					}
					//Close stderr
					close(STDERR_FILENO);
					//Redirect stderr on childlog
					if (dup2(fd, STDERR_FILENO) == -1) {
						fprintf(stderr, "Redirect stderr to ask password child log failed\n");
					}
					//Close childlog fd
					close(fd);
				}

				//Extract ask password pid
				if (extractAskPasswordPid(&askPasswordPid) < 0) {
					fprintf(stderr, "Failed to extract ask password pid");
					exit(EXIT_FAILURE);
				}

				//Close stdout and stderr without childlog
				if (fd == -1) {
					close(STDOUT_FILENO);
					close(STDERR_FILENO);
				}

				//Wait until get rattached to init(getppid()==1)
				//XXX: we are really blind here
				while(getppid() != 1) {
					//Sleep half a second
					if (usleep(500000) == -1 && fd != -1) {
						printf("Usleep failed\n");
					}
				}

				//Termitate ask password
				if (kill(askPasswordPid, 0) == 0 && kill(askPasswordPid, SIGTERM) == -1 && fd != -1) {
					printf("Termiate ask password failed\n");
				}


				//Sleep half a second
				if (usleep(500000) == -1 && fd != -1) {
					printf("Usleep failed\n");
				}

				//Kill ask password
				if (kill(askPasswordPid, 0) == 0 && kill(askPasswordPid, SIGKILL) == -1) {
					printf("Kill ask password failed\n");
				}

			//Parent process
			} else {

				//Process success
				header(200, "text/plain");
				printf("Sent value, boot should resume now");
				fflush(NULL);

			}

		}

	}

	exit(EXIT_SUCCESS);
}
