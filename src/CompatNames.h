/**
 * CompatNames.h — OPTIONAL legacy-name aliases for adopting this library
 * into an existing codebase.
 *
 * If your project already talks to a reader with the historical API names
 * (`Presence::Rc522NfcReader`, `Presence::Hce::buildSelectAid`,
 * `Presence::HceProof`, …), include this header and your existing call
 * sites compile unchanged instead of being renamed one by one. It is purely
 * an alias layer: the types are THE SAME types, so values cross the seam in
 * both directions with no copying or conversion.
 *
 * Do NOT include it in new code — it exists only for migration, and it is
 * deliberately not included by any library header, so it can never become a
 * hidden dependency.
 *
 * The host-safe protocol aliases live here; the Arduino-only driver aliases
 * (`Rc522NfcReader`, `TsLog`) are guarded so this header still compiles in
 * host tests.
 */
#pragma once

#include "HceProtocol.h"
#include "NfcReader.h"
#include "CardDebouncer.h"
#include "MockNfcReader.h"
#include "HceReader.h"

#if defined(ARDUINO)
#include "Rc522HceReader.h"
#include "TsLog.h"
#endif

// Types: exact aliases, so old and new names are interchangeable.
namespace Presence {

using HceProof = rc522hce::HceProof;
using NfcReader = rc522hce::NfcReader;
using CredentialKind = rc522hce::CredentialKind;
using HceReader = rc522hce::HceReader;
using CardDebouncer = rc522hce::CardDebouncer;
using MockNfcReader = rc522hce::MockNfcReader;
using MockSerialNfcReader = rc522hce::MockNfcReader;  // historical name

#if defined(ARDUINO)
using Rc522HceReader = rc522hce::Rc522HceReader;
using Rc522NfcReader = rc522hce::Rc522HceReader;  // historical name
using TsLog = rc522hce::TsLog;
#endif

// The protocol functions/enums/constants that used to live one namespace deeper.
namespace Hce {
using rc522hce::buildSelectAid;
using rc522hce::buildSelectAidWith;
using rc522hce::buildChallenge;
using rc522hce::buildEnroll;
using rc522hce::isOk;
using rc522hce::isKeyMissing;
using rc522hce::parseSelectResponse;
using rc522hce::parseChallengeResponse;
using rc522hce::parseEnrollResponse;
using rc522hce::hmacSha256;
using rc522hce::sha256Bytes;
using rc522hce::wrapKeyHex;
using rc522hce::unwrapKeyHex;
using rc522hce::chacha20Block;
using rc522hce::chacha20Poly1305Encrypt;
using rc522hce::chacha20Poly1305Decrypt;
using rc522hce::credentialKindName;
using rc522hce::credentialKindFromString;

using rc522hce::SelectOutcome;
using rc522hce::ChallengeResponse;
using rc522hce::CredentialKind;

using rc522hce::AID;
using rc522hce::AID_LEN;
using rc522hce::MAX_AID_LEN;
using rc522hce::NONCE_LEN;
using rc522hce::HMAC_LEN;
using rc522hce::MAX_CRED_LEN;
using rc522hce::KEY_LEN;
using rc522hce::KEY_NONCE_LEN;
using rc522hce::AEAD_KEY_LEN;
using rc522hce::AEAD_NONCE_LEN;
using rc522hce::AEAD_TAG_LEN;
using rc522hce::PROTOCOL_VERSION;
using rc522hce::KEY_WRAP_VERSION;

namespace TestVector = rc522hce::TestVector;  // namespace alias, not a using-decl
}  // namespace Hce

}  // namespace Presence

// Signer::toHex / sha256Hex used to be the home of these two helpers.
namespace Presence {
namespace Signer {
using rc522hce::toHex;
using rc522hce::sha256Hex;
}  // namespace Signer
}  // namespace Presence
