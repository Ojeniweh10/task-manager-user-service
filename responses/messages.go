package responses

import (
	"github.com/gofiber/fiber/v2"
)

type Response struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

func ErrorResponse(c *fiber.Ctx, message string, statusCode int) error {
	res := Response{
		Success: false,
		Message: message,
	}
	return c.Status(statusCode).JSON(res)
}

func SuccessResponse(c *fiber.Ctx, message string, data interface{}, statusCode int) error {
	res := Response{
		Success: true,
		Message: message,
		Data:    data,
	}
	return c.Status(statusCode).JSON(res)
}

const (
	UNAUTHORIZED_ACCESS       = "Unauthorized access"
	INCOMPLETE_DATA           = "Incomplete data"
	BAD_DATA                  = "You provided the wrong data format for one or more of the fields"
	EMAIL_EXIST               = "Email already in use"
	TELEPHONE_EXIST           = "Telephone already in use"
	EMAIL_TELEPHONE_EXIST     = "Email and Telephone already in use"
	INVALID_NAME              = "Invalid Name Format. Please check your lastname and/or firstname"
	INVALID_EMAIL             = "Invalid Email Format"
	INVALID_TELEPHONE         = "Invalid Telephone Format"
	LOGIN_SUCCESS             = "Login Successful"
	NO_ACCOUNT                = "account not found"
	UNVERIFIED_TELEPHONE      = "telephone number is not verified"
	INVALID_COUNTRY           = "Country not supported"
	WRONG_TELEPHONE           = "Wrong telephone number"
	UPDATE_APP                = "Please update your app"
	BAD_AUTHENTICATION        = "incorrect credentials"
	INVALID_OTP               = "invalid or expired Otp passed"
	TELEPHONE_VERIFIED        = "Telephone Successfully verified"
	USER_CREATED              = "Account Successfully Created"
	USER_DELETED              = "Account Successfully Deleted"
	OTP_SENT                  = "OTP has been successfully sent to your telephone"
	PASSWORD_CHANGED          = "Password successfully updated"
	EMAIL_CHANGED             = "Email successfully updated"
	WRONG_PASSWORD            = "wrong password passed"
	SOMETHING_WRONG           = "ooops! something went wrong. Please try again"
	INVALID_EMAIL_OTP         = "Wrong or expired email Otp passed"
	EMAIL_VERIFIED            = "Email successfully verified"
	BLOCKED_ACCOUNT           = "blocked account. please contact cashwise support via email at hello@cashwise.finance"
	USER_FETCHED              = "User(s) fetched successfully"
	NO_USER                   = "no user found"
	SECRET_QUESTION_SET       = "2FA set successfully"
	USER_DOES_NOT_EXIST       = "user does not exist"
	SECRET_UPDATED            = "2FA successfully updated"
	WRONG_SECRET_ANSWER       = "wrong secret answer passed"
	EMAIL_ALREADY_VERIFIED    = "Email address already verified"
	EMAIL_OTP_RESENT          = "One-Time-Passord (OTP) resent to your email"
	REFRESH_TOKEN_ERROR       = "unable to generate token"
	CONTACTS_CHECKED          = "contacts successfully checked"
	COMPLETE_KYC              = "please complete your kyc"
	DATA_FETCHED              = "data successfully fetched"
	ADDRESS_ADDED             = "Address successfully added"
	MUST_BE_18                = "User must be 18 years and above"
	KYC_LINK                  = "Kyc Link Generated"
	USER_ALREADY_VERIFIED     = "user has already been verified"
	PASSWORD_REUSE            = "you used this password recently. please choose a different one"
	VERIFICATION_SUCCESSFUL   = "Verification completed successfully"
	INVALID_ID_FORMAT         = "Invalid ID format"
	BVN_EXIST                 = "BVN already registered to someone else"
	USER_PENDING_APPROVAL     = "Your BVN verification is pending admin review."
	NIN_EXIST                 = "NIN already registered to someone else"
	USER_NIN_PENDING_APPROVAL = "Your NIN verification is pending admin review."
	DATA_PROCESSED            = "data processed successfully"
	NO_SELFIE                 = "you are required to take a selfie before verifying your identity"
	ID_PENDING_APPROVAL       = "Your ID verification is pending admin review."
)
