package com.hephaistos.appsign.core.ask

open class AppsignException(message: String, cause: Throwable? = null) : Exception(message, cause)

class AskFormatException(message: String, cause: Throwable? = null) :
  AppsignException(message, cause)

class AskPasswordRequiredException(
  message: String = "Password is required to unlock this ASK-LOCKED key container."
) : AppsignException(message)

class AskDecryptionException(
  message: String = "Unable to decrypt ASK container. Verify password and container integrity.",
  cause: Throwable? = null,
) : AppsignException(message, cause)

class AskKeyMismatchException(
  message: String = "Private key does not cryptographically match the stored X.509 certificate."
) : AppsignException(message)

class ApkOperationException(message: String, cause: Throwable? = null) :
  AppsignException(message, cause)
