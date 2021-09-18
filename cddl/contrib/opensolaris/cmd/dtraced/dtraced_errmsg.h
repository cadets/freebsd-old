#ifndef _DTRACED_ERRMSG_H_
#define _DTRACED_ERRMSG_H_

void be_quiet(void);
void dump_errmsg(const char *, ...);
void dump_warnmsg(const char *, ...);
void dump_debugmsg(const char *, ...);
void dump_backtrace(void);

#endif // _DTRACED_ERRMSG_H_
