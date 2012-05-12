{-# OPTIONS_GHC -fno-warn-missing-signatures #-}

-- all public
module Net.TLSCaps.EnumTexts where

import Data.Word (Word8, Word16)

-- versions
rv_ssl3_0 = 0x0300 :: Word16
rv_tls1_0 = 0x0301 :: Word16
rv_tls1_1 = 0x0302 :: Word16
rv_tls1_2 = 0x0303 :: Word16

-- record types
rt_change_cipher_spec = 20 :: Word8
rt_alert = 21 :: Word8
rt_handshake = 22 :: Word8
rt_application_data = 23 :: Word8

-- alert level
al_warning = 1 :: Word8
al_fatal = 2 :: Word8

-- alert descriptions
ad_close_notify = 0 :: Word8
ad_unexpected_message = 10 :: Word8
ad_bad_record_mac = 20 :: Word8
ad_decryption_failed_RESERVED = 21 :: Word8
ad_record_overflow = 22 :: Word8
ad_decompression_failure = 30 :: Word8
ad_handshake_failure = 40 :: Word8
ad_no_certificate_RESERVED = 41 :: Word8
ad_bad_certificate = 42 :: Word8
ad_unsupported_certificate = 43 :: Word8
ad_certificate_revoked = 44 :: Word8
ad_certificate_expired = 45 :: Word8
ad_certificate_unknown = 46 :: Word8
ad_illegal_parameter = 47 :: Word8
ad_unknown_ca = 48 :: Word8
ad_access_denied = 49 :: Word8
ad_decode_error = 50 :: Word8
ad_decrypt_error = 51 :: Word8
ad_export_restriction_RESERVED = 60 :: Word8
ad_protocol_version = 70 :: Word8
ad_insufficient_security = 71 :: Word8
ad_internal_error = 80 :: Word8
ad_user_canceled = 90 :: Word8
ad_no_renegotiation = 100 :: Word8
ad_unsupported_extension = 110 :: Word8
ad_certificate_unobtainable = 111 :: Word8
ad_unrecognized_name = 112 :: Word8
ad_bad_certificate_status_response = 113 :: Word8
ad_bad_certificate_hash_value = 114 :: Word8
ad_unknown_psk_identity = 115 :: Word8

-- handshake types
ht_hello_request = 0 :: Word8
ht_client_hello = 1 :: Word8
ht_server_hello = 2 :: Word8
ht_hello_verify_request = 3 :: Word8
ht_new_session_ticket = 4 :: Word8
ht_certificate = 11 :: Word8
ht_server_key_exchange  = 12 :: Word8
ht_certificate_request = 13 :: Word8
ht_server_hello_done = 14 :: Word8
ht_certificate_verify = 15 :: Word8
ht_client_key_exchange = 16 :: Word8
ht_finished = 20 :: Word8
ht_certificate_url = 21 :: Word8
ht_certificate_status = 22 :: Word8
ht_supplemental_data = 23 :: Word8

-- client certificate types
cct_rsa_sign = 1 :: Word8
cct_dss_sign = 2 :: Word8
cct_rsa_fixed_dh = 3 :: Word8
cct_dss_fixed_dh = 4 :: Word8
cct_rsa_ephemeral_dh_RESERVED = 5 :: Word8
cct_dss_ephemeral_dh_RESERVED = 6 :: Word8
cct_fortezza_dms_RESERVED = 20 :: Word8
cct_ecdsa_sign = 64 :: Word8
cct_rsa_fixed_ecdh = 65 :: Word8
cct_ecdsa_fixed_ecdh = 66 :: Word8

-- hash algorithms
ha_none = 0 :: Word8
ha_md5 = 1 :: Word8
ha_sha1 = 2 :: Word8
ha_sha224 = 3 :: Word8
ha_sha256 = 4 :: Word8
ha_sha384 = 5 :: Word8
ha_sha512 = 6 :: Word8

-- signature algorithms
sa_anonymous = 0 :: Word8
sa_rsa = 1 :: Word8
sa_dsa = 2 :: Word8
sa_ecdsa = 3 :: Word8

-- compression methods
comp_null = 0 :: Word8
comp_deflate = 1 :: Word8
comp_lzs = 64 :: Word8


versionText v
	| v == rv_ssl3_0 = "SSL3.0"
	| v == rv_tls1_0 = "TLS1.0"
	| v == rv_tls1_1 = "TLS1.1"
	| v == rv_tls1_2 = "TLS1.2"
	| otherwise = let tuple = divMod v 256 in "Version " ++ show tuple

recordTypeText rt
	| rt == rt_change_cipher_spec = "Change Cipher Spec"
	| rt == rt_alert = "Alert"
	| rt == rt_handshake = "Handshake"
	| rt == rt_application_data = "Application Data"
	| otherwise = "Unknown record type " ++ show rt

alertLevelText lvl
	| lvl == al_warning = "Warning"
	| lvl == al_fatal = "Fatal"
	| otherwise = "Unknown alert level " ++ show lvl

alertDescText desc
	| desc == ad_close_notify = "Close notify"
	| desc == ad_unexpected_message = "Unexpected message"
	| desc == ad_bad_record_mac = "Bad record mac"
	| desc == ad_decryption_failed_RESERVED = "Decryption failed"
	| desc == ad_record_overflow = "Record Overflow"
	| desc == ad_decompression_failure = "Decompression failure"
	| desc == ad_handshake_failure = "Handshake failure"
	| desc == ad_no_certificate_RESERVED = "No certificate"
	| desc == ad_bad_certificate = "Bad certificate"
	| desc == ad_unsupported_certificate = "Unsupported certificate"
	| desc == ad_certificate_revoked = "Certificate revoked"
	| desc == ad_certificate_expired = "Certificate expired"
	| desc == ad_certificate_unknown = "Certificate unknown"
	| desc == ad_illegal_parameter = "Illegal parameter"
	| desc == ad_unknown_ca = "Unknown CA"
	| desc == ad_access_denied = "Access denied"
	| desc == ad_decode_error = "Decode error"
	| desc == ad_decrypt_error = "Decrypt error"
	| desc == ad_export_restriction_RESERVED = "Export restriction"
	| desc == ad_protocol_version = "Protocol version"
	| desc == ad_insufficient_security = "Insufficient security"
	| desc == ad_internal_error = "Internal error"
	| desc == ad_user_canceled = "User canceled"
	| desc == ad_no_renegotiation = "No renegotiation"
	| desc == ad_unsupported_extension = "Unsupported extension"
	| desc == ad_certificate_unobtainable = "Certificate unobtainable"
	| desc == ad_unrecognized_name = "Unrecognized name"
	| desc == ad_bad_certificate_status_response = "Bad certificate status response"
	| desc == ad_bad_certificate_hash_value = "Bad certificate hash value"
	| desc == ad_unknown_psk_identity = "Unknown PSK identity"
	| otherwise = "Unknown alert " ++ show desc

handshakeTypeDesc ht
	| ht == ht_hello_request = "Hello request"
	| ht == ht_client_hello = "Client hello"
	| ht == ht_server_hello = "Server hello"
	| ht == ht_hello_verify_request = "Hello verify request"
	| ht == ht_new_session_ticket = "New session ticket"
	| ht == ht_certificate = "Certificate"
	| ht == ht_server_key_exchange = "Server key exchange"
	| ht == ht_certificate_request = "Certificate request"
	| ht == ht_server_hello_done = "Server hello done"
	| ht == ht_certificate_verify = "Certificate verify"
	| ht == ht_client_key_exchange = "Client key exchange"
	| ht == ht_finished = "Finished"
	| ht == ht_certificate_url = "Certificate url"
	| ht == ht_certificate_status = "Certificate status"
	| ht == ht_supplemental_data = "Supplemental data"
	| otherwise = "Unknown Handshake Type " ++ show ht

clientCertificateTypeDesc cct
	| cct == cct_rsa_sign = "RSA sign"
	| cct == cct_dss_sign = "DSS sign"
	| cct == cct_rsa_fixed_dh = "RSA fixed DH"
	| cct == cct_dss_fixed_dh = "DSS fixed DH"
	| cct == cct_rsa_ephemeral_dh_RESERVED = "RSA ephemeral DH"
	| cct == cct_dss_ephemeral_dh_RESERVED = "DSS ephemeral DH"
	| cct == cct_fortezza_dms_RESERVED = "Fortezza dms"
	| cct == cct_ecdsa_sign = "ECDSA sign"
	| cct == cct_rsa_fixed_ecdh = "RSA fixed ECDH"
	| cct == cct_ecdsa_fixed_ecdh = "ECDSA fixed ECDH"
	| otherwise = "Unknown client certificate type " ++ show cct

hashAlgorithmText ha
	| ha == ha_none = "None"
	| ha == ha_md5 = "MD5"
	| ha == ha_sha1 = "SHA1"
	| ha == ha_sha224 = "SHA224"
	| ha == ha_sha256 = "SHA256"
	| ha == ha_sha384 = "SHA384"
	| ha == ha_sha512 = "SHA512"
	| otherwise = "Unknown hash algorithm " ++ show ha

signatureAlgorithmText sa
	| sa == sa_anonymous = "Anonymous"
	| sa == sa_rsa = "RSA"
	| sa == sa_dsa = "DSA"
	| sa == sa_ecdsa = "ECDSA"
	| otherwise = "Unknown signature algorithm " ++ show sa

compressionMethodText comp
	| comp == comp_null = "NULL"
	| comp == comp_deflate = "DEFLATE"
	| comp == comp_lzs = "LZS"
	| otherwise = "Unknown compression method " ++ show comp
