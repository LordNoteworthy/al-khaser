#include "pch.h"
#include "log.h"

static int SESSION_TRACKER; //Keeps track of session

TCHAR* print_time()
{
	size_t size = 0;
	TCHAR *buf;
	errno_t err;
	TCHAR timestr[32];

	/* get current calendar time */
	time_t const sourceTime = time(NULL); 
	tm tmDest = { 0 };
	err = localtime_s(&tmDest, &sourceTime);
	if (err)
	{
		print_last_error(_T("localtime_s"));
		exit(1);
	}
	
	// Converts a time_t time value to a tm structure, and corrects for the local time zone. 
	err = _tasctime_s(timestr, 32, &tmDest);
	if (err)
	{
		print_last_error(_T("_tasctime_s"));
		exit(1);
	}

	//Getting rid of \n
	timestr[_tcsclen(timestr) - 1] = 0;

	//Additional +2 for square braces
	size = (_tcsclen(timestr) + 1 + 2) * sizeof(TCHAR);
	buf = (TCHAR*)malloc(size);
	if (buf) {
		memset(buf, 0x0, size);
		_stprintf_s(buf, size / sizeof(TCHAR), _T("[%s]"), timestr);
	}
	return buf;
}
void log_print(const TCHAR* filename, const TCHAR *fmt, ...)
{
	va_list list;
	const TCHAR *p, *r;
	int e;

	FILE *fp = NULL;
	errno_t error;

	TCHAR *pszTime;

	if (SESSION_TRACKER > 0)
		error = _tfopen_s(&fp, _T("log.txt"), _T("a+"));
	else
		error = _tfopen_s(&fp, _T("log.txt"), _T("w"));

	// file create/open failed
	if ((error != 0) || (fp == NULL))
		return;

	pszTime = print_time();
	if (pszTime) {
		_ftprintf(fp, _T("%s "), pszTime);
		free(pszTime);
	}
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
