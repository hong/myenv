#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>

static const char *wpa_conf_path = "/var/etc/wpa_supplicant.conf";
static const char *ctrl_iface_dir = "/var/run/wpa_supplicant";

struct wpa_ctrl {
    int s;
    struct sockaddr_un local;
    struct sockaddr_un dest;
};

static struct wpa_ctrl *ctrl_conn = NULL;

typedef enum {
    WPA_DISCONNECTED,        // Disconnected state
    WPA_INACTIVE,            // Inactive state (wpa_supplicant disabled)
    WPA_SCANNING,            // Scanning for a network
    WPA_ASSOCIATING,         // Trying to associate with a BSS/SSID
    WPA_ASSOCIATED,          // Association completed
    WPA_4WAY_HANDSHAKE,      // WPA 4-Way Key Handshake in progress
    WPA_GROUP_HANDSHAKE,     // WPA Group Key Handshake in progress
    WPA_COMPLETED,           // All authentication completed
} wpa_states;
 
static int wpa_ctrl_request(struct wpa_ctrl *ctrl, const char *cmd, size_t cmd_len,
             char *reply, size_t *reply_len)
{
    struct timeval tv;
    int res;
    fd_set rfds;
    const char *_cmd;
    char *cmd_buf = NULL;
    size_t _cmd_len;

    _cmd = cmd;
    _cmd_len = cmd_len;

    if (send(ctrl->s, _cmd, _cmd_len, 0) < 0) {
        return -1;
    }   
 
    for (;;) {
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        FD_ZERO(&rfds);
        FD_SET(ctrl->s, &rfds);
        res = select(ctrl->s + 1, &rfds, NULL, NULL, &tv);
        if (FD_ISSET(ctrl->s, &rfds)) {
            res = recv(ctrl->s, reply, *reply_len, 0);
            printf("reply=%s, res=%d\n", reply, res);
            if (res < 0)
                return res;
            if (res > 0 && reply[0] == '<') {
                /* This is an unsolicited message from
                 * wpa_supplicant, not the reply to the
                 * request. Use msg_cb to report this to the
                 * caller. */
                /*
                    if ((size_t) res == *reply_len)
                        res = (*reply_len) - 1;
                    reply[res] = '\0';
                    msg_cb(reply, res);
                    */
                continue;
            }       
            *reply_len = res;
            break;
        } else {
            return -2;
        }   
    } 

    return 0;
}

/****************************************/
/*    For check wpa_supplicant status   */
/****************************************/
static size_t strlcpy(char *dest, const char *src, size_t siz)
{            
    const char *s = src;
    size_t left = siz;
        
    if (left) {
        /* Copy string up to the maximum size of the dest buffer */
        while (--left != 0) {
            if ((*dest++ = *s++) == '\0')
                break;
        }
    }   
        
    if (left == 0) {
        /* Not enough room for the string; force NUL-termination */
        if (siz != 0)
            *dest = '\0';
        while (*s++)
            ; /* determine total src string length */
    }

    return s - src - 1;
}

struct wpa_ctrl * wpa_ctrl_open(const char *ctrl_path)
{
    struct wpa_ctrl *ctrl;
    static int counter = 0;
    int ret = 0;
    size_t res;
    int tries = 0;

    ctrl = (struct wpa_ctrl *)calloc(1, sizeof(*ctrl));
    if (ctrl == NULL)
        return NULL;

    ctrl->s = socket(PF_UNIX, SOCK_DGRAM, 0);
    if (ctrl->s < 0)
    {
        free(ctrl);
        return NULL;
    }

    ctrl->local.sun_family = AF_UNIX;

try_again:
    ret = snprintf(ctrl->local.sun_path, sizeof(ctrl->local.sun_path),
              "/tmp/wpa_ctrl_%d-%d", getpid(), counter);
    if (ret < 0 || (size_t) ret >= sizeof(ctrl->local.sun_path)) {
        close(ctrl->s);
        free(ctrl);
        return NULL;
    }   
    tries++;
    if (bind(ctrl->s, (struct sockaddr *) &ctrl->local,
            sizeof(ctrl->local)) < 0) {
        if (errno == EADDRINUSE && tries < 2) {
            /*
             * getpid() returns unique identifier for this instance
             * of wpa_ctrl, so the existing socket file must have
             * been left by unclean termination of an earlier run.
             * Remove the file and try again.
             */
            unlink(ctrl->local.sun_path);
            goto try_again;
        }    
        close(ctrl->s);
        free(ctrl);
    }   
        
    ctrl->dest.sun_family = AF_UNIX;
    res = strlcpy(ctrl->dest.sun_path, ctrl_path,
             sizeof(ctrl->dest.sun_path));
    if (res >= sizeof(ctrl->dest.sun_path)) {
        close(ctrl->s);
        free(ctrl);
        return NULL;
    }
    if (connect(ctrl->s, (struct sockaddr *) &ctrl->dest,
            sizeof(ctrl->dest)) < 0) {
        close(ctrl->s);
        unlink(ctrl->local.sun_path);
        free(ctrl);
        return NULL;
    }   
        
    return ctrl;
}

static int wpa_cli_ctrl_command(struct wpa_ctrl *ctrl, char *cmd, char* buf)
{
    size_t len;
    int ret;

    if (ctrl_conn == NULL) {
        printf("Not connected to wpa_supplicant - command dropped.\n");
        return -1;
    }
    len = strlen(buf) - 1;
    printf("len = %d, cmd = %s\n", len, cmd);
    ret = wpa_ctrl_request(ctrl, cmd, strlen(cmd), buf, &len);
    if (ret == -2) {
        printf("'%s' command timed out.\n", cmd);
        return -2;
    } else if (ret < 0) {
        printf("'%s' command failed.\n", cmd);
        return -1;
    }

    printf("%s\n", buf);
    buf[len] = '\0';
    return 0;
}

static struct wpa_ctrl* wpa_cli_open_connection(const char *ifname)
{
    char *cfile;
    int flen, res;

    if (ifname == NULL)
        return NULL;

    printf("ifname=%s\n", ifname);
    flen = strlen(ctrl_iface_dir) + strlen(ifname) + 2;
    cfile = (char *)calloc(1, flen);
    printf("cfile=%p\n", cfile);
    if (cfile == NULL)
        return NULL;
    res = snprintf(cfile, flen, "%s/%s", ctrl_iface_dir, ifname);
    if (res < 0 || res >= flen) {
        free(cfile);
        return NULL;
    }

    ctrl_conn = wpa_ctrl_open(cfile);
    printf("ctrl_conn=%p\n", ctrl_conn);
    free(cfile);
    return ctrl_conn;
}

static void wpa_cli_close_connection(void)
{
    if (ctrl_conn == NULL)
        return;

    unlink(ctrl_conn->local.sun_path);
    close(ctrl_conn->s);
    free(ctrl_conn);
    ctrl_conn = NULL;
}

int main(int argc , char *argv[])
{
    int ret = 0;
    char buf[64] = "";

    /* create a client connection for wpa */
    ctrl_conn = wpa_cli_open_connection("wlan0");
    if (ctrl_conn == NULL)
        return -1;

    ret = wpa_cli_ctrl_command(ctrl_conn, "STATUS", buf);
	fprintf(stdout, "ret=%d, buf=%s\n", ret, buf);

    wpa_cli_close_connection();
    return 0;
}
