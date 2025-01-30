SIMPLE Protocol Implementation

Overview

This repository contains an implementation of the SIMPLE (Secure IoT Memory-Protected Lightweight Attestation) protocol, which is a remote attestation scheme designed for resource-constrained IoT devices.
SIMPLE ensures software integrity by enabling a verifier to authenticate a remote device (prover) using cryptographic authentication and a monotonic counter.

This implementation simulates the protocol in a Linux environment using pseudo-terminals (PTY) to emulate UART communication. The cryptographic operations (HMAC-SHA256) are performed using OpenSSL.

Project Components

The implementation consists of three main components:

    verifier.c: The trusted entity that initiates the attestation process. It sends an attestation request containing a counter, a nonce, and a valid software state. It verifies the prover’s response.
    prover.c: The device being attested. It verifies the authenticity of the request, checks its freshness, and responds with an attestation report.
    microvisor.c: A simulated microvisor environment that securely stores cryptographic keys and provides controlled access to them.
