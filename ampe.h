#ifndef __AMPE_H
#define __AMPE_H
/**
 * process_plink_frame - protect peer link management frames
 * gets unsecured mesh peering management frames and returns self protected
 * frames with the right AMPE fields.  All processing is done in place, so
 * the returned frame is ready to be sent.
 *
 * @frame: On input, the peer link management frame to be protected. On output,
 * the self-protected peer link management frame.
 * @len: On input, the length of the peer link management passed in. On output,
 * the size of the self-protected frame.
 * @max_len: The size of the entire buffer pointed by frame that's made available
 * to this function.  This should be sufficient to hold a self-protected output
 * frame.  If not, the function will return -ENOMEM.
 * Returns: 0 on success, negative on failure.
 */
int process_plink_frame (struct ieee80211_mgmt_frame *frame, int *len, int max_len);
#endif
