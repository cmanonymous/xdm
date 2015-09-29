#ifndef __HADM_ACCT_H
#define __HADM_ACCT_H
/* perharps, could remove to common.inc */

enum acct_entry {
	R_BIO,
	W_BIO,
	R_WRAPPER,
	W_WRAPPER,
	R_SUBMIT_WRAPPER,
	W_SUBMIT_WRAPPER = 5,
	R_SUBBIO,
	W_SUBBIO,
	W_SUBBIO_SET_ENDIO,
	R_SUBBIO_FINISH,
	W_SUBBIO_FINISH = 10,
	R_BIO_FINISH,
	W_BIO_FINISH,

	MAX_ACCOUT_ENTRY,
};

#endif	/* __HADM_ACCT_H */
