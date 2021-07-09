#include "pch.h"
#include "CheckResult.h"

CheckResult::CheckResult(CheckStatus status)
{
	this->Status = status;
}

CheckResult::CheckResult(CheckStatus status, const char* message, ...)
{
	this->Status = status;
	va_list args;
	va_start(args, message);
	this->_message = string_format(message, args);
	va_end(args);
}

CheckResult::CheckResult(CheckStatus status, const char* message, va_list args)
{
	this->Status = status;
	this->_message = string_format(message, args);
}

void CheckResult::Log(const char* message, ...)
{
	va_list args;
	va_start(args, message);
	auto logLine = string_format(message, args);
	this->_log.append(logLine);
	this->_log.append("\n");
	va_end(args);
}

const char* CheckResult::GetMessage()
{
	return this->_message.c_str();
}

const char* CheckResult::GetLog()
{
	return this->_log.c_str();
}

/* static builder methods */

CheckResult CheckResult::Undetected()
{
	return CheckResult(CheckStatus::Undetected);
}

CheckResult CheckResult::Undetected(const char* message, ...)
{
	va_list args;
	va_start(args, message);
	auto result = CheckResult(CheckStatus::Undetected, message, args);
	va_end(args);
	return result;
}

CheckResult CheckResult::Detected()
{
	return CheckResult(CheckStatus::Detected);
}

CheckResult CheckResult::Detected(const char* message, ...)
{
	va_list args;
	va_start(args, message);
	auto result = CheckResult(CheckStatus::Detected, message, args);
	va_end(args);
	return result;
}

CheckResult CheckResult::Inconclusive()
{
	return CheckResult(CheckStatus::Inconclusive);
}

CheckResult CheckResult::Inconclusive(const char* message, ...)
{
	va_list args;
	va_start(args, message);
	auto result = CheckResult(CheckStatus::Inconclusive, message, args);
	va_end(args);
	return result;
}

CheckResult CheckResult::Error()
{
	return CheckResult(CheckStatus::Error);
}

CheckResult CheckResult::Error(const char* message, ...)
{
	va_list args;
	va_start(args, message);
	auto result = CheckResult(CheckStatus::Error, message, args);
	va_end(args);
	return result;
}

CheckResult CheckResult::Invalid()
{
	return CheckResult(CheckStatus::Invalid);
}

CheckResult CheckResult::Invalid(const char* message, ...)
{
	va_list args;
	va_start(args, message);
	auto result = CheckResult(CheckStatus::Invalid, message, args);
	va_end(args);
	return result;
}
