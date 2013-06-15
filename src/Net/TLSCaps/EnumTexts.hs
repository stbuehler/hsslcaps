{-# OPTIONS_GHC -fno-warn-missing-signatures #-}

-- all public
module Net.TLSCaps.EnumTexts
	( TLSVersion(..)
	, toTLSVersion
	, fromTLSVersion

	, TLSRecordType(..)
	, toTLSRecordType
	, fromTLSRecordType

	, TLSAlertLevel(..)
	, toTLSAlertLevel
	, fromTLSAlertLevel

	, TLSAlertDescription(..)
	, toTLSAlertDescription
	, fromTLSAlertDescription

	, TLSHandshakeType(..)
	, toTLSHandshakeType
	, fromTLSHandshakeType

	, TLSClientCertificateType(..)
	, toTLSClientCertificateType
	, fromTLSClientCertificateType

	, TLSHashAlgorithm(..)
	, toTLSHashAlgorithm
	, fromTLSHashAlgorithm

	, TLSSignatureAlgorithm(..)
	, toTLSSignatureAlgorithm
	, fromTLSSignatureAlgorithm

	, TLSCompressionMethod(..)
	, toTLSCompressionMethod
	, fromTLSCompressionMethod

	, CipherSuite(..)
	, MacAlgorithm(..)
	, CipherAlgorithm(..)
	, toCipherSuite
	, fromCipherSuite
	, cipherSuiteInfo
	) where

import Data.Word (Word8, Word16)

-- export them here too
import Net.TLSCaps.CipherSuites

-- versions
newtype TLSVersionRaw = TLSVersionRaw Word16 deriving (Eq)
data TLSVersion = SSL3_0 | TLS1_0 | TLS1_1 | TLS1_2 | TLSVersion_Raw !TLSVersionRaw deriving (Eq)

toTLSVersion :: Word16 -> TLSVersion
toTLSVersion 0x0300 = SSL3_0
toTLSVersion 0x0301 = TLS1_0
toTLSVersion 0x0302 = TLS1_1
toTLSVersion 0x0303 = TLS1_2
toTLSVersion x = TLSVersion_Raw $ TLSVersionRaw x

fromTLSVersion :: TLSVersion -> Word16
fromTLSVersion SSL3_0 = 0x0300
fromTLSVersion TLS1_0 = 0x0301
fromTLSVersion TLS1_1 = 0x0302
fromTLSVersion TLS1_2 = 0x0303
fromTLSVersion (TLSVersion_Raw (TLSVersionRaw x)) = x

instance Bounded TLSVersion where
	minBound = toTLSVersion minBound
	maxBound = toTLSVersion maxBound
instance Enum TLSVersion where
	toEnum = toTLSVersion . toEnum
	fromEnum = fromEnum . fromTLSVersion
instance Ord TLSVersion where
	(<=) x y = (<=) (fromTLSVersion x) (fromTLSVersion y)
instance Show TLSVersion where
	show SSL3_0 = "SSL3.0"
	show TLS1_0 = "TLS1.0"
	show TLS1_1 = "TLS1.1"
	show TLS1_2 = "TLS1.2"
	show (TLSVersion_Raw (TLSVersionRaw x)) = let tuple = divMod x 256 in "Version " ++ show tuple

-- record types
newtype TLSRecordTypeRaw = TLSRecordTypeRaw Word8 deriving (Eq)
data TLSRecordType = TLS_RT_ChangeCipherSpec | TLS_RT_Alert | TLS_RT_Handshake | TLS_RT_ApplicationData | TLS_RT_Heartbeat | TLS_RT_Raw !TLSRecordTypeRaw deriving (Eq)

toTLSRecordType :: Word8 -> TLSRecordType
toTLSRecordType 20 = TLS_RT_ChangeCipherSpec
toTLSRecordType 21 = TLS_RT_Alert
toTLSRecordType 22 = TLS_RT_Handshake
toTLSRecordType 23 = TLS_RT_ApplicationData
toTLSRecordType 24 = TLS_RT_Heartbeat
toTLSRecordType x  = TLS_RT_Raw $ TLSRecordTypeRaw x

fromTLSRecordType :: TLSRecordType -> Word8
fromTLSRecordType TLS_RT_ChangeCipherSpec = 20
fromTLSRecordType TLS_RT_Alert            = 21
fromTLSRecordType TLS_RT_Handshake        = 22
fromTLSRecordType TLS_RT_ApplicationData  = 23
fromTLSRecordType TLS_RT_Heartbeat        = 24
fromTLSRecordType (TLS_RT_Raw (TLSRecordTypeRaw x)) = x

instance Bounded TLSRecordType where
	minBound = toTLSRecordType minBound
	maxBound = toTLSRecordType maxBound
instance Enum TLSRecordType where
	toEnum = toTLSRecordType . toEnum
	fromEnum = fromEnum . fromTLSRecordType
instance Ord TLSRecordType where
	(<=) x y = (<=) (fromTLSRecordType x) (fromTLSRecordType y)
instance Show TLSRecordType where
	show TLS_RT_ChangeCipherSpec = "Change Cipher Spec"
	show TLS_RT_Alert = "Alert"
	show TLS_RT_Handshake = "Handshake"
	show TLS_RT_ApplicationData = "Application Data"
	show TLS_RT_Heartbeat = "Heartbeat"
	show (TLS_RT_Raw (TLSRecordTypeRaw x)) = "Unknown record type " ++ show x

-- alert level
newtype TLSAlertLevelRaw = TLSAlertLevelRaw Word8 deriving (Eq)
data TLSAlertLevel = TLS_Warning | TLS_Fatal | TLS_AlertLevel_Raw !TLSAlertLevelRaw deriving (Eq)

toTLSAlertLevel :: Word8 -> TLSAlertLevel
toTLSAlertLevel 1 = TLS_Warning
toTLSAlertLevel 2 = TLS_Fatal
toTLSAlertLevel x = TLS_AlertLevel_Raw $ TLSAlertLevelRaw x

fromTLSAlertLevel :: TLSAlertLevel -> Word8
fromTLSAlertLevel TLS_Warning = 1
fromTLSAlertLevel TLS_Fatal = 2
fromTLSAlertLevel (TLS_AlertLevel_Raw (TLSAlertLevelRaw x)) = x

instance Bounded TLSAlertLevel where
	minBound = toTLSAlertLevel minBound
	maxBound = toTLSAlertLevel maxBound
instance Enum TLSAlertLevel where
	toEnum = toTLSAlertLevel . toEnum
	fromEnum = fromEnum . fromTLSAlertLevel
instance Ord TLSAlertLevel where
	(<=) x y = (<=) (fromTLSAlertLevel x) (fromTLSAlertLevel y)
instance Show TLSAlertLevel where
	show TLS_Warning = "Warning"
	show TLS_Fatal = "Fatal"
	show (TLS_AlertLevel_Raw (TLSAlertLevelRaw x)) = "Unknown alert level " ++ show x

-- alert descriptions
newtype TLSAlertDescriptionRaw = TLSAlertDescriptionRaw Word8 deriving (Eq)
data TLSAlertDescription = TLS_Alert_close_notify | TLS_Alert_unexpected_message | TLS_Alert_bad_record_mac | TLS_Alert_decryption_failed_RESERVED | TLS_Alert_record_overflow | TLS_Alert_decompression_failure
	| TLS_Alert_handshake_failure | TLS_Alert_no_certificate_RESERVED | TLS_Alert_bad_certificate | TLS_Alert_unsupported_certificate | TLS_Alert_certificate_revoked | TLS_Alert_certificate_expired
	| TLS_Alert_certificate_unknown | TLS_Alert_illegal_parameter | TLS_Alert_unknown_ca | TLS_Alert_access_denied | TLS_Alert_decode_error | TLS_Alert_decrypt_error | TLS_Alert_export_restriction_RESERVED
	| TLS_Alert_protocol_version | TLS_Alert_insufficient_security | TLS_Alert_internal_error | TLS_Alert_user_canceled | TLS_Alert_no_renegotiation | TLS_Alert_unsupported_extension
	| TLS_Alert_certificate_unobtainable | TLS_Alert_unrecognized_name | TLS_Alert_bad_certificate_status_response | TLS_Alert_bad_certificate_hash_value | TLS_Alert_unknown_psk_identity
	| TLS_AlertDescription_Raw !TLSAlertDescriptionRaw deriving (Eq)

toTLSAlertDescription :: Word8 -> TLSAlertDescription
toTLSAlertDescription 0   = TLS_Alert_close_notify
toTLSAlertDescription 10  = TLS_Alert_unexpected_message
toTLSAlertDescription 20  = TLS_Alert_bad_record_mac
toTLSAlertDescription 21  = TLS_Alert_decryption_failed_RESERVED
toTLSAlertDescription 22  = TLS_Alert_record_overflow
toTLSAlertDescription 30  = TLS_Alert_decompression_failure
toTLSAlertDescription 40  = TLS_Alert_handshake_failure
toTLSAlertDescription 41  = TLS_Alert_no_certificate_RESERVED
toTLSAlertDescription 42  = TLS_Alert_bad_certificate
toTLSAlertDescription 43  = TLS_Alert_unsupported_certificate
toTLSAlertDescription 44  = TLS_Alert_certificate_revoked
toTLSAlertDescription 45  = TLS_Alert_certificate_expired
toTLSAlertDescription 46  = TLS_Alert_certificate_unknown
toTLSAlertDescription 47  = TLS_Alert_illegal_parameter
toTLSAlertDescription 48  = TLS_Alert_unknown_ca
toTLSAlertDescription 49  = TLS_Alert_access_denied
toTLSAlertDescription 50  = TLS_Alert_decode_error
toTLSAlertDescription 51  = TLS_Alert_decrypt_error
toTLSAlertDescription 60  = TLS_Alert_export_restriction_RESERVED
toTLSAlertDescription 70  = TLS_Alert_protocol_version
toTLSAlertDescription 71  = TLS_Alert_insufficient_security
toTLSAlertDescription 80  = TLS_Alert_internal_error
toTLSAlertDescription 90  = TLS_Alert_user_canceled
toTLSAlertDescription 100 = TLS_Alert_no_renegotiation
toTLSAlertDescription 110 = TLS_Alert_unsupported_extension
toTLSAlertDescription 111 = TLS_Alert_certificate_unobtainable
toTLSAlertDescription 112 = TLS_Alert_unrecognized_name
toTLSAlertDescription 113 = TLS_Alert_bad_certificate_status_response
toTLSAlertDescription 114 = TLS_Alert_bad_certificate_hash_value
toTLSAlertDescription 115 = TLS_Alert_unknown_psk_identity
toTLSAlertDescription x   = TLS_AlertDescription_Raw $ TLSAlertDescriptionRaw x

fromTLSAlertDescription :: TLSAlertDescription -> Word8
fromTLSAlertDescription TLS_Alert_close_notify                    = 0
fromTLSAlertDescription TLS_Alert_unexpected_message              = 10
fromTLSAlertDescription TLS_Alert_bad_record_mac                  = 20
fromTLSAlertDescription TLS_Alert_decryption_failed_RESERVED      = 21
fromTLSAlertDescription TLS_Alert_record_overflow                 = 22
fromTLSAlertDescription TLS_Alert_decompression_failure           = 30
fromTLSAlertDescription TLS_Alert_handshake_failure               = 40
fromTLSAlertDescription TLS_Alert_no_certificate_RESERVED         = 41
fromTLSAlertDescription TLS_Alert_bad_certificate                 = 42
fromTLSAlertDescription TLS_Alert_unsupported_certificate         = 43
fromTLSAlertDescription TLS_Alert_certificate_revoked             = 44
fromTLSAlertDescription TLS_Alert_certificate_expired             = 45
fromTLSAlertDescription TLS_Alert_certificate_unknown             = 46
fromTLSAlertDescription TLS_Alert_illegal_parameter               = 47
fromTLSAlertDescription TLS_Alert_unknown_ca                      = 48
fromTLSAlertDescription TLS_Alert_access_denied                   = 49
fromTLSAlertDescription TLS_Alert_decode_error                    = 50
fromTLSAlertDescription TLS_Alert_decrypt_error                   = 51
fromTLSAlertDescription TLS_Alert_export_restriction_RESERVED     = 60
fromTLSAlertDescription TLS_Alert_protocol_version                = 70
fromTLSAlertDescription TLS_Alert_insufficient_security           = 71
fromTLSAlertDescription TLS_Alert_internal_error                  = 80
fromTLSAlertDescription TLS_Alert_user_canceled                   = 90
fromTLSAlertDescription TLS_Alert_no_renegotiation                = 100
fromTLSAlertDescription TLS_Alert_unsupported_extension           = 110
fromTLSAlertDescription TLS_Alert_certificate_unobtainable        = 111
fromTLSAlertDescription TLS_Alert_unrecognized_name               = 112
fromTLSAlertDescription TLS_Alert_bad_certificate_status_response = 113
fromTLSAlertDescription TLS_Alert_bad_certificate_hash_value      = 114
fromTLSAlertDescription TLS_Alert_unknown_psk_identity            = 115
fromTLSAlertDescription (TLS_AlertDescription_Raw (TLSAlertDescriptionRaw x)) = x

instance Bounded TLSAlertDescription where
	minBound = toTLSAlertDescription minBound
	maxBound = toTLSAlertDescription maxBound
instance Enum TLSAlertDescription where
	toEnum = toTLSAlertDescription . toEnum
	fromEnum = fromEnum . fromTLSAlertDescription
instance Ord TLSAlertDescription where
	(<=) x y = (<=) (fromTLSAlertDescription x) (fromTLSAlertDescription y)
instance Show TLSAlertDescription where
	show TLS_Alert_close_notify                    = "Close notify"
	show TLS_Alert_unexpected_message              = "Unexpected message"
	show TLS_Alert_bad_record_mac                  = "Bad record mac"
	show TLS_Alert_decryption_failed_RESERVED      = "Decryption failed"
	show TLS_Alert_record_overflow                 = "Record Overflow"
	show TLS_Alert_decompression_failure           = "Decompression failure"
	show TLS_Alert_handshake_failure               = "Handshake failure"
	show TLS_Alert_no_certificate_RESERVED         = "No certificate"
	show TLS_Alert_bad_certificate                 = "Bad certificate"
	show TLS_Alert_unsupported_certificate         = "Unsupported certificate"
	show TLS_Alert_certificate_revoked             = "Certificate revoked"
	show TLS_Alert_certificate_expired             = "Certificate expired"
	show TLS_Alert_certificate_unknown             = "Certificate unknown"
	show TLS_Alert_illegal_parameter               = "Illegal parameter"
	show TLS_Alert_unknown_ca                      = "Unknown CA"
	show TLS_Alert_access_denied                   = "Access denied"
	show TLS_Alert_decode_error                    = "Decode error"
	show TLS_Alert_decrypt_error                   = "Decrypt error"
	show TLS_Alert_export_restriction_RESERVED     = "Export restriction"
	show TLS_Alert_protocol_version                = "Protocol version"
	show TLS_Alert_insufficient_security           = "Insufficient security"
	show TLS_Alert_internal_error                  = "Internal error"
	show TLS_Alert_user_canceled                   = "User canceled"
	show TLS_Alert_no_renegotiation                = "No renegotiation"
	show TLS_Alert_unsupported_extension           = "Unsupported extension"
	show TLS_Alert_certificate_unobtainable        = "Certificate unobtainable"
	show TLS_Alert_unrecognized_name               = "Unrecognized name"
	show TLS_Alert_bad_certificate_status_response = "Bad certificate status response"
	show TLS_Alert_bad_certificate_hash_value      = "Bad certificate hash value"
	show TLS_Alert_unknown_psk_identity            = "Unknown PSK identity"
	show (TLS_AlertDescription_Raw (TLSAlertDescriptionRaw x)) = "Unknown alert " ++ show x

-- handshake types
newtype TLSHandshakeTypeRaw = TLSHandshakeTypeRaw Word8 deriving (Eq)
data TLSHandshakeType = TLS_HT_HelloRequest | TLS_HT_ClientHello | TLS_HT_ServerHello | TLS_HT_HelloVerifyRequest | TLS_HT_NewSessionTicket | TLS_HT_Certificate
	| TLS_HT_ServerKeyExchange | TLS_HT_CertificateRequest | TLS_HT_ServerHelloDone | TLS_HT_CertificateVerify | TLS_HT_ClientKeyExchange
	| TLS_HT_Finished | TLS_HT_CertificateUrl | TLS_HT_CertificateStatus | TLS_HT_SupplementalData
	| TLS_HT_Raw !TLSHandshakeTypeRaw deriving (Eq)

toTLSHandshakeType :: Word8 -> TLSHandshakeType
toTLSHandshakeType 0  = TLS_HT_HelloRequest
toTLSHandshakeType 1  = TLS_HT_ClientHello
toTLSHandshakeType 2  = TLS_HT_ServerHello
toTLSHandshakeType 3  = TLS_HT_HelloVerifyRequest
toTLSHandshakeType 4  = TLS_HT_NewSessionTicket
toTLSHandshakeType 11 = TLS_HT_Certificate
toTLSHandshakeType 12 = TLS_HT_ServerKeyExchange
toTLSHandshakeType 13 = TLS_HT_CertificateRequest
toTLSHandshakeType 14 = TLS_HT_ServerHelloDone
toTLSHandshakeType 15 = TLS_HT_CertificateVerify
toTLSHandshakeType 16 = TLS_HT_ClientKeyExchange
toTLSHandshakeType 20 = TLS_HT_Finished
toTLSHandshakeType 21 = TLS_HT_CertificateUrl
toTLSHandshakeType 22 = TLS_HT_CertificateStatus
toTLSHandshakeType 23 = TLS_HT_SupplementalData
toTLSHandshakeType x  = TLS_HT_Raw $ TLSHandshakeTypeRaw x

fromTLSHandshakeType :: TLSHandshakeType -> Word8
fromTLSHandshakeType TLS_HT_HelloRequest       = 0
fromTLSHandshakeType TLS_HT_ClientHello        = 1
fromTLSHandshakeType TLS_HT_ServerHello        = 2
fromTLSHandshakeType TLS_HT_HelloVerifyRequest = 3
fromTLSHandshakeType TLS_HT_NewSessionTicket   = 4
fromTLSHandshakeType TLS_HT_Certificate        = 11
fromTLSHandshakeType TLS_HT_ServerKeyExchange  = 12
fromTLSHandshakeType TLS_HT_CertificateRequest = 13
fromTLSHandshakeType TLS_HT_ServerHelloDone    = 14
fromTLSHandshakeType TLS_HT_CertificateVerify  = 15
fromTLSHandshakeType TLS_HT_ClientKeyExchange  = 16
fromTLSHandshakeType TLS_HT_Finished           = 20
fromTLSHandshakeType TLS_HT_CertificateUrl     = 21
fromTLSHandshakeType TLS_HT_CertificateStatus  = 22
fromTLSHandshakeType TLS_HT_SupplementalData   = 23
fromTLSHandshakeType (TLS_HT_Raw (TLSHandshakeTypeRaw x)) = x

instance Bounded TLSHandshakeType where
	minBound = toTLSHandshakeType minBound
	maxBound = toTLSHandshakeType maxBound
instance Enum TLSHandshakeType where
	toEnum = toTLSHandshakeType . toEnum
	fromEnum = fromEnum . fromTLSHandshakeType
instance Ord TLSHandshakeType where
	(<=) x y = (<=) (fromTLSHandshakeType x) (fromTLSHandshakeType y)
instance Show TLSHandshakeType where
	show TLS_HT_HelloRequest       = "Hello request"
	show TLS_HT_ClientHello        = "Client hello"
	show TLS_HT_ServerHello        = "Server hello"
	show TLS_HT_HelloVerifyRequest = "Hello verify request"
	show TLS_HT_NewSessionTicket   = "New session ticket"
	show TLS_HT_Certificate        = "Certificate"
	show TLS_HT_ServerKeyExchange  = "Server key exchange"
	show TLS_HT_CertificateRequest = "Certificate request"
	show TLS_HT_ServerHelloDone    = "Server hello done"
	show TLS_HT_CertificateVerify  = "Certificate verify"
	show TLS_HT_ClientKeyExchange  = "Client key exchange"
	show TLS_HT_Finished           = "Finished"
	show TLS_HT_CertificateUrl     = "Certificate url"
	show TLS_HT_CertificateStatus  = "Certificate status"
	show TLS_HT_SupplementalData   = "Supplemental data"
	show (TLS_HT_Raw (TLSHandshakeTypeRaw x)) = "Unknown Handshake Type " ++ show x

-- client certificate types
newtype TLSClientCertificateTypeRaw = TLSClientCertificateTypeRaw Word8 deriving (Eq)
data TLSClientCertificateType = TLS_CCT_rsa_sign | TLS_CCT_dss_sign | TLS_CCT_rsa_fixed_dh | TLS_CCT_dss_fixed_dh | TLS_CCT_rsa_ephemeral_dh_RESERVED
	| TLS_CCT_dss_ephemeral_dh_RESERVED | TLS_CCT_fortezza_dms_RESERVED | TLS_CCT_ecdsa_sign | TLS_CCT_rsa_fixed_ecdh | TLS_CCT_ecdsa_fixed_ecdh
	| TLS_ClientCertificateType_Raw !TLSClientCertificateTypeRaw deriving (Eq)

toTLSClientCertificateType :: Word8 -> TLSClientCertificateType
toTLSClientCertificateType 1  = TLS_CCT_rsa_sign
toTLSClientCertificateType 2  = TLS_CCT_dss_sign
toTLSClientCertificateType 3  = TLS_CCT_rsa_fixed_dh
toTLSClientCertificateType 4  = TLS_CCT_dss_fixed_dh
toTLSClientCertificateType 5  = TLS_CCT_rsa_ephemeral_dh_RESERVED
toTLSClientCertificateType 6  = TLS_CCT_dss_ephemeral_dh_RESERVED
toTLSClientCertificateType 20 = TLS_CCT_fortezza_dms_RESERVED
toTLSClientCertificateType 64 = TLS_CCT_ecdsa_sign
toTLSClientCertificateType 65 = TLS_CCT_rsa_fixed_ecdh
toTLSClientCertificateType 66 = TLS_CCT_ecdsa_fixed_ecdh
toTLSClientCertificateType x  = TLS_ClientCertificateType_Raw $ TLSClientCertificateTypeRaw x

fromTLSClientCertificateType :: TLSClientCertificateType -> Word8
fromTLSClientCertificateType TLS_CCT_rsa_sign                  = 1
fromTLSClientCertificateType TLS_CCT_dss_sign                  = 2
fromTLSClientCertificateType TLS_CCT_rsa_fixed_dh              = 3
fromTLSClientCertificateType TLS_CCT_dss_fixed_dh              = 4
fromTLSClientCertificateType TLS_CCT_rsa_ephemeral_dh_RESERVED = 5
fromTLSClientCertificateType TLS_CCT_dss_ephemeral_dh_RESERVED = 6
fromTLSClientCertificateType TLS_CCT_fortezza_dms_RESERVED     = 20
fromTLSClientCertificateType TLS_CCT_ecdsa_sign                = 64
fromTLSClientCertificateType TLS_CCT_rsa_fixed_ecdh            = 65
fromTLSClientCertificateType TLS_CCT_ecdsa_fixed_ecdh          = 66
fromTLSClientCertificateType (TLS_ClientCertificateType_Raw (TLSClientCertificateTypeRaw x)) = x

instance Bounded TLSClientCertificateType where
	minBound = toTLSClientCertificateType minBound
	maxBound = toTLSClientCertificateType maxBound
instance Enum TLSClientCertificateType where
	toEnum = toTLSClientCertificateType . toEnum
	fromEnum = fromEnum . fromTLSClientCertificateType
instance Ord TLSClientCertificateType where
	(<=) x y = (<=) (fromTLSClientCertificateType x) (fromTLSClientCertificateType y)
instance Show TLSClientCertificateType where
	show TLS_CCT_rsa_sign = "RSA sign"
	show TLS_CCT_dss_sign = "DSS sign"
	show TLS_CCT_rsa_fixed_dh = "RSA fixed DH"
	show TLS_CCT_dss_fixed_dh = "DSS fixed DH"
	show TLS_CCT_rsa_ephemeral_dh_RESERVED = "RSA ephemeral DH"
	show TLS_CCT_dss_ephemeral_dh_RESERVED = "DSS ephemeral DH"
	show TLS_CCT_fortezza_dms_RESERVED = "Fortezza dms"
	show TLS_CCT_ecdsa_sign = "ECDSA sign"
	show TLS_CCT_rsa_fixed_ecdh = "RSA fixed ECDH"
	show TLS_CCT_ecdsa_fixed_ecdh = "ECDSA fixed ECDH"
	show (TLS_ClientCertificateType_Raw (TLSClientCertificateTypeRaw x)) = "Unknown client certificate type " ++ show x

-- hash algorithms
newtype TLSHashAlgorithmRaw = TLSHashAlgorithmRaw Word8 deriving (Eq)
data TLSHashAlgorithm = TLS_Hash_None | TLS_MD5 | TLS_SHA1 | TLS_SHA224 | TLS_SHA256 | TLS_SHA384 | TLS_SHA512
	| TLS_HashAlgorithm_Raw !TLSHashAlgorithmRaw deriving (Eq)

toTLSHashAlgorithm :: Word8 -> TLSHashAlgorithm
toTLSHashAlgorithm 0 = TLS_Hash_None
toTLSHashAlgorithm 1 = TLS_MD5
toTLSHashAlgorithm 2 = TLS_SHA1
toTLSHashAlgorithm 3 = TLS_SHA224
toTLSHashAlgorithm 4 = TLS_SHA256
toTLSHashAlgorithm 5 = TLS_SHA384
toTLSHashAlgorithm 6 = TLS_SHA512
toTLSHashAlgorithm x = TLS_HashAlgorithm_Raw $ TLSHashAlgorithmRaw x

fromTLSHashAlgorithm :: TLSHashAlgorithm -> Word8
fromTLSHashAlgorithm TLS_Hash_None = 0
fromTLSHashAlgorithm TLS_MD5       = 1
fromTLSHashAlgorithm TLS_SHA1      = 2
fromTLSHashAlgorithm TLS_SHA224    = 3
fromTLSHashAlgorithm TLS_SHA256    = 4
fromTLSHashAlgorithm TLS_SHA384    = 5
fromTLSHashAlgorithm TLS_SHA512    = 6
fromTLSHashAlgorithm (TLS_HashAlgorithm_Raw (TLSHashAlgorithmRaw x)) = x

instance Bounded TLSHashAlgorithm where
	minBound = toTLSHashAlgorithm minBound
	maxBound = toTLSHashAlgorithm maxBound
instance Enum TLSHashAlgorithm where
	toEnum = toTLSHashAlgorithm . toEnum
	fromEnum = fromEnum . fromTLSHashAlgorithm
instance Ord TLSHashAlgorithm where
	(<=) x y = (<=) (fromTLSHashAlgorithm x) (fromTLSHashAlgorithm y)
instance Show TLSHashAlgorithm where
	show TLS_Hash_None = "no hash"
	show TLS_MD5 = "MD5"
	show TLS_SHA1 = "SHA1"
	show TLS_SHA224 = "SHA224"
	show TLS_SHA256 = "SHA256"
	show TLS_SHA384 = "SHA384"
	show TLS_SHA512 = "SHA512"
	show (TLS_HashAlgorithm_Raw (TLSHashAlgorithmRaw x)) = "Unknown hash algorithm " ++ show x

-- signature algorithms
newtype TLSSignatureAlgorithmRaw = TLSSignatureAlgorithmRaw Word8 deriving (Eq)
data TLSSignatureAlgorithm = TLS_SA_ANONYMOUS | TLS_SA_RSA | TLS_SA_DSA | TLS_SA_ECDSA
	| TLS_SignatureAlgorithm_Raw !TLSSignatureAlgorithmRaw deriving (Eq)

toTLSSignatureAlgorithm :: Word8 -> TLSSignatureAlgorithm
toTLSSignatureAlgorithm 0 = TLS_SA_ANONYMOUS
toTLSSignatureAlgorithm 1 = TLS_SA_RSA
toTLSSignatureAlgorithm 2 = TLS_SA_DSA
toTLSSignatureAlgorithm 3 = TLS_SA_ECDSA
toTLSSignatureAlgorithm x = TLS_SignatureAlgorithm_Raw $ TLSSignatureAlgorithmRaw x

fromTLSSignatureAlgorithm :: TLSSignatureAlgorithm -> Word8
fromTLSSignatureAlgorithm TLS_SA_ANONYMOUS = 0
fromTLSSignatureAlgorithm TLS_SA_RSA       = 1
fromTLSSignatureAlgorithm TLS_SA_DSA       = 2
fromTLSSignatureAlgorithm TLS_SA_ECDSA     = 3
fromTLSSignatureAlgorithm (TLS_SignatureAlgorithm_Raw (TLSSignatureAlgorithmRaw x)) = x

instance Bounded TLSSignatureAlgorithm where
	minBound = toTLSSignatureAlgorithm minBound
	maxBound = toTLSSignatureAlgorithm maxBound
instance Enum TLSSignatureAlgorithm where
	toEnum = toTLSSignatureAlgorithm . toEnum
	fromEnum = fromEnum . fromTLSSignatureAlgorithm
instance Ord TLSSignatureAlgorithm where
	(<=) x y = (<=) (fromTLSSignatureAlgorithm x) (fromTLSSignatureAlgorithm y)
instance Show TLSSignatureAlgorithm where
	show TLS_SA_ANONYMOUS = "Anonymous"
	show TLS_SA_RSA       = "RSA"
	show TLS_SA_DSA       = "DSA"
	show TLS_SA_ECDSA     = "ECDSA"
	show (TLS_SignatureAlgorithm_Raw (TLSSignatureAlgorithmRaw x)) = "Unknown signature algorithm " ++ show x


-- compression methods
newtype TLSCompressionMethodRaw = TLSCompressionMethodRaw Word8 deriving (Eq)
data TLSCompressionMethod = TLS_Comp_None | TLS_DEFLATE | TLS_LZS | TLS_CompressionMethod_Raw !TLSCompressionMethodRaw deriving (Eq)

toTLSCompressionMethod :: Word8 -> TLSCompressionMethod
toTLSCompressionMethod 0  =TLS_Comp_None
toTLSCompressionMethod 1  =TLS_DEFLATE
toTLSCompressionMethod 64 =TLS_LZS
toTLSCompressionMethod x  = TLS_CompressionMethod_Raw $ TLSCompressionMethodRaw x

fromTLSCompressionMethod :: TLSCompressionMethod -> Word8
fromTLSCompressionMethod TLS_Comp_None = 0
fromTLSCompressionMethod TLS_DEFLATE   = 1
fromTLSCompressionMethod TLS_LZS       = 64
fromTLSCompressionMethod (TLS_CompressionMethod_Raw (TLSCompressionMethodRaw x)) = x

instance Bounded TLSCompressionMethod where
	minBound = toTLSCompressionMethod minBound
	maxBound = toTLSCompressionMethod maxBound
instance Enum TLSCompressionMethod where
	toEnum = toTLSCompressionMethod . toEnum
	fromEnum = fromEnum . fromTLSCompressionMethod
instance Ord TLSCompressionMethod where
	(<=) x y = (<=) (fromTLSCompressionMethod x) (fromTLSCompressionMethod y)
instance Show TLSCompressionMethod where
	show TLS_Comp_None = "no compression"
	show TLS_DEFLATE   = "DEFLATE"
	show TLS_LZS       = "LZS"
	show (TLS_CompressionMethod_Raw (TLSCompressionMethodRaw x)) = "Unknown compression method " ++ show x
