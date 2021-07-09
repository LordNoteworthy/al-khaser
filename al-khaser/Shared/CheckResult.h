#pragma once

/// Ternary helper macro that returns CheckResult::Detected() if the given expression is true, otherwise CheckResult::Undetected()
#define DETECTED_IF_TRUE(b) ((!!(b)) ? CheckResult::Detected() : CheckResult::Undetected())
/// Ternary helper macro that returns CheckResult::Detected() if the given expression is false, otherwise CheckResult::Undetected()
#define DETECTED_IF_FALSE(b) ((!(b)) ? CheckResult::Detected() : CheckResult::Undetected())

#define RESULT_DETECTED (CheckResult::Detected())
#define RESULT_UNDETECTED (CheckResult::Undetected())

enum CheckStatus
{
	/// The check did not detect anything.
	Undetected,
	/// The check detected something.
	Detected,
	/// The check found inconclusive results.
	Inconclusive,
	/// The check could not be completed due to an error.
	Error,
	/// The check was not valid for this system.
	Invalid
};

class CheckResult
{
private:
	std::string _message;
	std::string _log;

	CheckResult(CheckStatus status, const char* message, va_list args);

public:
	/* fields */

	CheckStatus Status;

	/* constructors */

	CheckResult(CheckStatus status);
	CheckResult(CheckStatus status, const char* message, ...);

	/* methods */

	void Log(const char* message, ...);

	const char* GetMessage();
	const char* GetLog();

	bool IsDetected();
	bool IsUndetected();
	bool IsInconclusive();
	bool IsError();
	bool IsInvalid();

	/* static builders for common check results */

	/// Creates a Undetected result.
	static CheckResult Undetected();
	/// Creates a Undetected result, with a formatted message.
	/// <param name="message">The message to include in the check result. This message will only be included in verbose output.</param>
	static CheckResult Undetected(const char* message, ...);

	/// Creates a Detected result.
	static CheckResult Detected();
	/// Creates a Detected result, with a formatted message.
	/// <param name="message">The message to include in the check result. This message will only be included in verbose output.</param>
	static CheckResult Detected(const char* message, ...);

	/// Creates an Inconclusive result. An inconclusive result should be returned when the check could not identify whether there was or wasn't a detection, for some reason other than an error.
	static CheckResult Inconclusive();
	/// Creates an Inconclusive result, with a formatted message. An inconclusive result should be returned when the check could not identify whether there was or wasn't a detection, for some reason other than an error.
	/// <param name="message">The message to include in the check result. This message will only be included in verbose output.</param>
	static CheckResult Inconclusive(const char* message, ...);

	/// Creates an Error result.
	static CheckResult Error();
	/// Creates an Error result, with a formatted message.
	/// <param name="message">The message to include in the check result. This message will only be included in verbose output.</param>
	static CheckResult Error(const char* message, ...);


	/// Creates a Invalid result. An invalid result should be returned when a check is not valid on the system (e.g. a 32-bit only check on a 64-bit system).
	static CheckResult Invalid();
	/// Creates a Invalid result, with a formatted message. An invalid result should be returned when a check is not valid on the system (e.g. a 32-bit only check on a 64-bit system).
	/// <param name="message">The message to include in the check result. This message will only be included in verbose output.</param>
	static CheckResult Invalid(const char* message, ...);
};
