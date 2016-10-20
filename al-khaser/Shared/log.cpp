#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include "log.h"

FILE *fp;
static int SESSION_TRACKER; //Keeps track of session

TCHAR* print_time()
{
	int size = 0;
	time_t t;
	TCHAR *buf;

	t = time(NULL); /* get current calendar time */

	TCHAR *timestr = _tasctime(localtime(&t));
	timestr[_tcsclen(timestr) - 1] = 0;  //Getting rid of \n

	size = (_tcsclen(timestr) + 1 + 2) * sizeof(TCHAR); //Additional +2 for square braces
	buf = (TCHAR*)malloc(size);

	memset(buf, 0x0, size);
	_stprintf_s(buf, size,_T("[%s]"), timestr);

	return buf;
}
void log_print(TCHAR* filename, TCHAR *fmt, ...)
{
	va_list list;
	TCHAR *p, *r;
	int e;

	if (SESSION_TRACKER > 0)
		fp = _tfopen(_T("log.txt"), _T("a+"));
	else
		fp = _tfopen(_T("log.txt"), _T("w"));

	_ftprintf(fp, _T("%s "), print_time());
	va_start(list, fmt);

	for (p = fmt; *p; ++p)
	{
		if (*p != '%')//If simple string
			fputc(*p, fp);

		else
		{
			switch (*++p)
			{
				/* string */
			case 's':
			{
				r = va_arg(list, TCHAR *);
				_ftprintf(fp, _T("%s"), r);
				continue;
			}

			/* integer */
			case 'd':
			{
				e = va_arg(list, int);
				_ftprintf(fp, _T("%d"), e);
				continue;
			}

			default:
				fputc(*p, fp);
			}
		}
	}
	va_end(list);
	fputc('\n', fp);
	SESSION_TRACKER++;
	fclose(fp);
}