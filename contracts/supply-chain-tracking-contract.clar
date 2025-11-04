(define-constant contract-owner tx-sender)
(define-constant err-owner-only (err u100))
(define-constant err-not-found (err u101))
(define-constant err-already-exists (err u102))
(define-constant err-unauthorized (err u103))
(define-constant err-invalid-stage (err u104))
(define-constant err-invalid-transfer (err u105))
(define-constant err-product-recalled (err u106))
(define-constant err-recall-not-found (err u107))
(define-constant err-recall-already-exists (err u108))
(define-constant err-auth-code-exists (err u109))
(define-constant err-auth-code-not-found (err u110))
(define-constant err-invalid-auth-code (err u111))
(define-constant err-condition-violation (err u112))
(define-constant err-no-conditions-set (err u113))
(define-constant err-invalid-range (err u114))

(define-map products
    { product-id: uint }
    {
        name: (string-ascii 100),
        manufacturer: principal,
        created-at: uint,
        current-owner: principal,
        current-stage: (string-ascii 50),
        is-verified: bool,
    }
)

(define-map product-history
    {
        product-id: uint,
        event-id: uint,
    }
    {
        stage: (string-ascii 50),
        location: (string-ascii 100),
        timestamp: uint,
        actor: principal,
        notes: (string-ascii 200),
    }
)

(define-map authorized-actors
    { actor: principal }
    {
        role: (string-ascii 50),
        authorized: bool,
    }
)

(define-map ephemeral-authorizations
    { actor: principal }
    {
        expires-at: uint,
        active: bool,
    }
)

(define-map product-recalls
    { recall-id: uint }
    {
        product-id: uint,
        reason: (string-ascii 200),
        severity: (string-ascii 20),
        initiated-by: principal,
        initiated-at: uint,
        status: (string-ascii 20),
        affected-batches: (string-ascii 100),
    }
)

(define-map recall-acknowledgments
    {
        recall-id: uint,
        actor: principal,
    }
    {
        acknowledged-at: uint,
        action-taken: (string-ascii 100),
        notes: (string-ascii 200),
    }
)

(define-map product-auth-codes
    { product-id: uint }
    {
        auth-code: (string-ascii 32),
        generated-at: uint,
        generated-by: principal,
        verification-count: uint,
        last-verified-at: (optional uint),
    }
)

(define-map auth-verifications
    { verification-id: uint }
    {
        product-id: uint,
        auth-code: (string-ascii 32),
        verifier: principal,
        timestamp: uint,
        is-authentic: bool,
        location: (optional (string-ascii 100)),
    }
)

(define-map suspicious-activities
    { activity-id: uint }
    {
        reported-product-id: uint,
        invalid-auth-code: (string-ascii 32),
        reporter: principal,
        timestamp: uint,
        location: (optional (string-ascii 100)),
        notes: (string-ascii 200),
    }
)

(define-map product-conditions
    { product-id: uint }
    {
        min-temp: int,
        max-temp: int,
        min-humidity: uint,
        max-humidity: uint,
        set-by: principal,
        set-at: uint,
    }
)

(define-map condition-readings
    { reading-id: uint }
    {
        product-id: uint,
        temperature: int,
        humidity: uint,
        recorded-by: principal,
        recorded-at: uint,
        location: (optional (string-ascii 100)),
        is-violation: bool,
    }
)

(define-map condition-violations
    { violation-id: uint }
    {
        product-id: uint,
        reading-id: uint,
        violation-type: (string-ascii 20),
        recorded-value: int,
        expected-range: (string-ascii 50),
        timestamp: uint,
        auto-flagged: bool,
    }
)

(define-data-var next-product-id uint u1)
(define-data-var next-event-id uint u1)
(define-data-var next-recall-id uint u1)
(define-data-var next-verification-id uint u1)
(define-data-var next-activity-id uint u1)
(define-data-var next-reading-id uint u1)
(define-data-var next-violation-id uint u1)

(define-public (authorize-actor
        (actor principal)
        (role (string-ascii 50))
    )
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (ok (map-set authorized-actors { actor: actor } {
            role: role,
            authorized: true,
        }))
    )
)

(define-public (revoke-actor (actor principal))
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (ok (map-set authorized-actors { actor: actor } {
            role: "",
            authorized: false,
        }))
    )
)

(define-read-only (is-authorized (actor principal))
    (let (
            (permanent (map-get? authorized-actors { actor: actor }))
            (ephemeral (map-get? ephemeral-authorizations { actor: actor }))
        )
        (or
            (match permanent
                auth-data (get authorized auth-data)
                false
            )
            (match ephemeral
                token (and (get active token) (>= (get expires-at token) stacks-block-height))
                false
            )
        )
    )
)

(define-public (grant-ephemeral-authorization
        (actor principal)
        (expires-at uint)
    )
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (asserts! (> expires-at stacks-block-height) err-invalid-range)
        (ok (map-set ephemeral-authorizations { actor: actor } {
            expires-at: expires-at,
            active: true,
        }))
    )
)

(define-public (revoke-ephemeral-authorization (actor principal))
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (ok (map-set ephemeral-authorizations { actor: actor } {
            expires-at: stacks-block-height,
            active: false,
        }))
    )
)

(define-read-only (get-ephemeral-authorization (actor principal))
    (map-get? ephemeral-authorizations { actor: actor })
)

(define-public (register-product
        (name (string-ascii 100))
        (manufacturer principal)
        (initial-stage (string-ascii 50))
        (location (string-ascii 100))
    )
    (let (
            (product-id (var-get next-product-id))
            (event-id (var-get next-event-id))
        )
        (asserts! (or (is-eq tx-sender contract-owner) (is-authorized tx-sender))
            err-unauthorized
        )
        (asserts!
            (map-insert products { product-id: product-id } {
                name: name,
                manufacturer: manufacturer,
                created-at: stacks-block-height,
                current-owner: manufacturer,
                current-stage: initial-stage,
                is-verified: true,
            })
            err-already-exists
        )
        (asserts!
            (map-insert product-history {
                product-id: product-id,
                event-id: event-id,
            } {
                stage: initial-stage,
                location: location,
                timestamp: stacks-block-height,
                actor: tx-sender,
                notes: "Product registered",
            })
            err-already-exists
        )
        (var-set next-product-id (+ product-id u1))
        (var-set next-event-id (+ event-id u1))
        (ok product-id)
    )
)

(define-public (update-product-stage
        (product-id uint)
        (new-stage (string-ascii 50))
        (location (string-ascii 100))
        (notes (string-ascii 200))
    )
    (let (
            (product-data (unwrap! (map-get? products { product-id: product-id }) err-not-found))
            (event-id (var-get next-event-id))
        )
        (asserts! (or (is-eq tx-sender contract-owner) (is-authorized tx-sender))
            err-unauthorized
        )
        (asserts! (not (is-product-recalled product-id)) err-product-recalled)
        (map-set products { product-id: product-id }
            (merge product-data { current-stage: new-stage })
        )
        (asserts!
            (map-insert product-history {
                product-id: product-id,
                event-id: event-id,
            } {
                stage: new-stage,
                location: location,
                timestamp: stacks-block-height,
                actor: tx-sender,
                notes: notes,
            })
            err-already-exists
        )
        (var-set next-event-id (+ event-id u1))
        (ok true)
    )
)

(define-public (transfer-ownership
        (product-id uint)
        (new-owner principal)
        (location (string-ascii 100))
        (notes (string-ascii 200))
    )
    (let (
            (product-data (unwrap! (map-get? products { product-id: product-id }) err-not-found))
            (event-id (var-get next-event-id))
            (current-owner (get current-owner product-data))
        )
        (asserts!
            (or
                (is-eq tx-sender current-owner)
                (is-eq tx-sender contract-owner)
                (is-authorized tx-sender)
            )
            err-unauthorized
        )
        (asserts! (not (is-product-recalled product-id)) err-product-recalled)
        (map-set products { product-id: product-id }
            (merge product-data { current-owner: new-owner })
        )
        (asserts!
            (map-insert product-history {
                product-id: product-id,
                event-id: event-id,
            } {
                stage: "transferred",
                location: location,
                timestamp: stacks-block-height,
                actor: tx-sender,
                notes: notes,
            })
            err-already-exists
        )
        (var-set next-event-id (+ event-id u1))
        (ok true)
    )
)

(define-public (verify-product (product-id uint))
    (let ((product-data (unwrap! (map-get? products { product-id: product-id }) err-not-found)))
        (asserts! (or (is-eq tx-sender contract-owner) (is-authorized tx-sender))
            err-unauthorized
        )
        (ok (map-set products { product-id: product-id }
            (merge product-data { is-verified: true })
        ))
    )
)

(define-public (flag-product (product-id uint))
    (let ((product-data (unwrap! (map-get? products { product-id: product-id }) err-not-found)))
        (asserts! (or (is-eq tx-sender contract-owner) (is-authorized tx-sender))
            err-unauthorized
        )
        (ok (map-set products { product-id: product-id }
            (merge product-data { is-verified: false })
        ))
    )
)

(define-read-only (get-product (product-id uint))
    (map-get? products { product-id: product-id })
)

(define-read-only (get-product-history
        (product-id uint)
        (event-id uint)
    )
    (map-get? product-history {
        product-id: product-id,
        event-id: event-id,
    })
)

(define-read-only (get-current-stage (product-id uint))
    (match (map-get? products { product-id: product-id })
        product-data (some (get current-stage product-data))
        none
    )
)

(define-read-only (get-current-owner (product-id uint))
    (match (map-get? products { product-id: product-id })
        product-data (some (get current-owner product-data))
        none
    )
)

(define-read-only (is-product-verified (product-id uint))
    (match (map-get? products { product-id: product-id })
        product-data (get is-verified product-data)
        false
    )
)

(define-read-only (get-manufacturer (product-id uint))
    (match (map-get? products { product-id: product-id })
        product-data (some (get manufacturer product-data))
        none
    )
)

(define-read-only (get-next-product-id)
    (var-get next-product-id)
)

(define-read-only (get-next-event-id)
    (var-get next-event-id)
)

(define-read-only (get-actor-role (actor principal))
    (match (map-get? authorized-actors { actor: actor })
        auth-data (some (get role auth-data))
        none
    )
)

(define-public (batch-update-stages (updates (list
    20
    {
        product-id: uint,
        stage: (string-ascii 50),
        location: (string-ascii 100),
        notes: (string-ascii 200),
    }
)))
    (begin
        (asserts! (or (is-eq tx-sender contract-owner) (is-authorized tx-sender))
            err-unauthorized
        )
        (fold batch-update-helper updates (ok true))
    )
)

(define-private (batch-update-helper
        (update {
            product-id: uint,
            stage: (string-ascii 50),
            location: (string-ascii 100),
            notes: (string-ascii 200),
        })
        (prev-result (response bool uint))
    )
    (match prev-result
        success (update-product-stage (get product-id update) (get stage update)
            (get location update) (get notes update)
        )
        error-val (err error-val)
    )
)

(define-public (emergency-stop (product-id uint))
    (let (
            (product-data (unwrap! (map-get? products { product-id: product-id }) err-not-found))
            (event-id (var-get next-event-id))
        )
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (map-set products { product-id: product-id }
            (merge product-data {
                current-stage: "EMERGENCY_STOP",
                is-verified: false,
            })
        )
        (asserts!
            (map-insert product-history {
                product-id: product-id,
                event-id: event-id,
            } {
                stage: "EMERGENCY_STOP",
                location: "SYSTEM",
                timestamp: stacks-block-height,
                actor: tx-sender,
                notes: "Emergency stop initiated",
            })
            err-already-exists
        )
        (var-set next-event-id (+ event-id u1))
        (ok true)
    )
)

(define-read-only (is-product-recalled (product-id uint))
    (get found
        (fold check-recall-for-product (list u1 u2 u3 u4 u5 u6 u7 u8 u9 u10) {
            product-id: product-id,
            found: false,
        })
    )
)

(define-private (check-recall-for-product
        (recall-id uint)
        (state {
            product-id: uint,
            found: bool,
        })
    )
    (let ((product-id (get product-id state)))
        (if (get found state)
            state
            (match (map-get? product-recalls { recall-id: recall-id })
                recall-data (if (and
                        (is-eq (get product-id recall-data) product-id)
                        (is-eq (get status recall-data) "active")
                    )
                    {
                        product-id: product-id,
                        found: true,
                    }
                    state
                )
                state
            )
        )
    )
)

(define-public (initiate-product-recall
        (product-id uint)
        (reason (string-ascii 200))
        (severity (string-ascii 20))
        (affected-batches (string-ascii 100))
    )
    (let (
            (recall-id (var-get next-recall-id))
            (product-data (unwrap! (map-get? products { product-id: product-id }) err-not-found))
        )
        (asserts! (or (is-eq tx-sender contract-owner) (is-authorized tx-sender))
            err-unauthorized
        )
        (asserts!
            (map-insert product-recalls { recall-id: recall-id } {
                product-id: product-id,
                reason: reason,
                severity: severity,
                initiated-by: tx-sender,
                initiated-at: stacks-block-height,
                status: "active",
                affected-batches: affected-batches,
            })
            err-recall-already-exists
        )
        (map-set products { product-id: product-id }
            (merge product-data {
                current-stage: "RECALLED",
                is-verified: false,
            })
        )
        (var-set next-recall-id (+ recall-id u1))
        (ok recall-id)
    )
)

(define-public (acknowledge-recall
        (recall-id uint)
        (action-taken (string-ascii 100))
        (notes (string-ascii 200))
    )
    (let ((recall-data (unwrap! (map-get? product-recalls { recall-id: recall-id })
            err-recall-not-found
        )))
        (asserts! (or (is-eq tx-sender contract-owner) (is-authorized tx-sender))
            err-unauthorized
        )
        (asserts!
            (map-insert recall-acknowledgments {
                recall-id: recall-id,
                actor: tx-sender,
            } {
                acknowledged-at: stacks-block-height,
                action-taken: action-taken,
                notes: notes,
            })
            err-already-exists
        )
        (ok true)
    )
)

(define-public (resolve-recall (recall-id uint))
    (let ((recall-data (unwrap! (map-get? product-recalls { recall-id: recall-id })
            err-recall-not-found
        )))
        (asserts! (or (is-eq tx-sender contract-owner) (is-authorized tx-sender))
            err-unauthorized
        )
        (ok (map-set product-recalls { recall-id: recall-id }
            (merge recall-data { status: "resolved" })
        ))
    )
)

(define-read-only (get-recall-info (recall-id uint))
    (map-get? product-recalls { recall-id: recall-id })
)

(define-read-only (get-recall-acknowledgment
        (recall-id uint)
        (actor principal)
    )
    (map-get? recall-acknowledgments {
        recall-id: recall-id,
        actor: actor,
    })
)

(define-read-only (get-next-recall-id)
    (var-get next-recall-id)
)

(define-public (generate-auth-code
        (product-id uint)
        (auth-code (string-ascii 32))
    )
    (let ((product-data (unwrap! (map-get? products { product-id: product-id }) err-not-found)))
        (asserts! (or (is-eq tx-sender contract-owner) (is-authorized tx-sender))
            err-unauthorized
        )
        (asserts!
            (map-insert product-auth-codes { product-id: product-id } {
                auth-code: auth-code,
                generated-at: stacks-block-height,
                generated-by: tx-sender,
                verification-count: u0,
                last-verified-at: none,
            })
            err-auth-code-exists
        )
        (ok auth-code)
    )
)

(define-public (verify-product-authenticity
        (product-id uint)
        (auth-code (string-ascii 32))
        (location (optional (string-ascii 100)))
    )
    (let (
            (verification-id (var-get next-verification-id))
            (auth-data (map-get? product-auth-codes { product-id: product-id }))
        )
        (match auth-data
            valid-auth (let ((is-authentic (is-eq (get auth-code valid-auth) auth-code)))
                (asserts!
                    (map-insert auth-verifications { verification-id: verification-id } {
                        product-id: product-id,
                        auth-code: auth-code,
                        verifier: tx-sender,
                        timestamp: stacks-block-height,
                        is-authentic: is-authentic,
                        location: location,
                    })
                    err-already-exists
                )
                (if is-authentic
                    (begin
                        (map-set product-auth-codes { product-id: product-id }
                            (merge valid-auth {
                                verification-count: (+ (get verification-count valid-auth) u1),
                                last-verified-at: (some stacks-block-height),
                            })
                        )
                        (var-set next-verification-id (+ verification-id u1))
                        (ok true)
                    )
                    (begin
                        (var-set next-verification-id (+ verification-id u1))
                        (ok false)
                    )
                )
            )
            (begin
                (asserts!
                    (map-insert auth-verifications { verification-id: verification-id } {
                        product-id: product-id,
                        auth-code: auth-code,
                        verifier: tx-sender,
                        timestamp: stacks-block-height,
                        is-authentic: false,
                        location: location,
                    })
                    err-already-exists
                )
                (var-set next-verification-id (+ verification-id u1))
                (ok false)
            )
        )
    )
)

(define-public (report-suspicious-activity
        (product-id uint)
        (invalid-auth-code (string-ascii 32))
        (location (optional (string-ascii 100)))
        (notes (string-ascii 200))
    )
    (let ((activity-id (var-get next-activity-id)))
        (asserts!
            (map-insert suspicious-activities { activity-id: activity-id } {
                reported-product-id: product-id,
                invalid-auth-code: invalid-auth-code,
                reporter: tx-sender,
                timestamp: stacks-block-height,
                location: location,
                notes: notes,
            })
            err-already-exists
        )
        (var-set next-activity-id (+ activity-id u1))
        (ok activity-id)
    )
)

(define-read-only (get-auth-code (product-id uint))
    (map-get? product-auth-codes { product-id: product-id })
)

(define-read-only (get-verification-details (verification-id uint))
    (map-get? auth-verifications { verification-id: verification-id })
)

(define-read-only (get-suspicious-activity (activity-id uint))
    (map-get? suspicious-activities { activity-id: activity-id })
)

(define-read-only (get-product-verification-stats (product-id uint))
    (match (map-get? product-auth-codes { product-id: product-id })
        auth-data (some {
            verification-count: (get verification-count auth-data),
            last-verified-at: (get last-verified-at auth-data),
            generated-at: (get generated-at auth-data),
            generated-by: (get generated-by auth-data),
        })
        none
    )
)

(define-read-only (get-next-verification-id)
    (var-get next-verification-id)
)

(define-read-only (get-next-activity-id)
    (var-get next-activity-id)
)

(define-public (set-product-conditions
        (product-id uint)
        (min-temp int)
        (max-temp int)
        (min-humidity uint)
        (max-humidity uint)
    )
    (let ((product-data (unwrap! (map-get? products { product-id: product-id }) err-not-found)))
        (asserts! (or (is-eq tx-sender contract-owner) (is-authorized tx-sender))
            err-unauthorized
        )
        (asserts! (< min-temp max-temp) err-invalid-range)
        (asserts! (< min-humidity max-humidity) err-invalid-range)
        (ok (map-set product-conditions { product-id: product-id } {
            min-temp: min-temp,
            max-temp: max-temp,
            min-humidity: min-humidity,
            max-humidity: max-humidity,
            set-by: tx-sender,
            set-at: stacks-block-height,
        }))
    )
)

(define-public (record-condition-reading
        (product-id uint)
        (temperature int)
        (humidity uint)
        (location (optional (string-ascii 100)))
    )
    (let (
            (reading-id (var-get next-reading-id))
            (conditions (map-get? product-conditions { product-id: product-id }))
        )
        (unwrap! (map-get? products { product-id: product-id }) err-not-found)
        (match conditions
            valid-conditions (let (
                    (temp-violation (or
                        (< temperature (get min-temp valid-conditions))
                        (> temperature (get max-temp valid-conditions))
                    ))
                    (humidity-violation (or
                        (< humidity (get min-humidity valid-conditions))
                        (> humidity (get max-humidity valid-conditions))
                    ))
                    (is-violation (or temp-violation humidity-violation))
                )
                (asserts!
                    (map-insert condition-readings { reading-id: reading-id } {
                        product-id: product-id,
                        temperature: temperature,
                        humidity: humidity,
                        recorded-by: tx-sender,
                        recorded-at: stacks-block-height,
                        location: location,
                        is-violation: is-violation,
                    })
                    err-already-exists
                )
                (if temp-violation
                    (try! (log-violation product-id reading-id "temperature"
                        temperature (get min-temp valid-conditions)
                        (get max-temp valid-conditions)
                    ))
                    true
                )
                (if humidity-violation
                    (try! (log-violation-humidity product-id reading-id
                        (to-int humidity)
                        (to-int (get min-humidity valid-conditions))
                        (to-int (get max-humidity valid-conditions))
                    ))
                    true
                )
                (var-set next-reading-id (+ reading-id u1))
                (ok reading-id)
            )
            (begin
                (asserts!
                    (map-insert condition-readings { reading-id: reading-id } {
                        product-id: product-id,
                        temperature: temperature,
                        humidity: humidity,
                        recorded-by: tx-sender,
                        recorded-at: stacks-block-height,
                        location: location,
                        is-violation: false,
                    })
                    err-already-exists
                )
                (var-set next-reading-id (+ reading-id u1))
                (ok reading-id)
            )
        )
    )
)

(define-private (log-violation
        (product-id uint)
        (reading-id uint)
        (violation-type (string-ascii 20))
        (recorded-value int)
        (min-val int)
        (max-val int)
    )
    (let ((violation-id (var-get next-violation-id)))
        (asserts!
            (map-insert condition-violations { violation-id: violation-id } {
                product-id: product-id,
                reading-id: reading-id,
                violation-type: violation-type,
                recorded-value: recorded-value,
                expected-range: "temp-range",
                timestamp: stacks-block-height,
                auto-flagged: true,
            })
            err-already-exists
        )
        (var-set next-violation-id (+ violation-id u1))
        (ok true)
    )
)

(define-private (log-violation-humidity
        (product-id uint)
        (reading-id uint)
        (recorded-value int)
        (min-val int)
        (max-val int)
    )
    (let ((violation-id (var-get next-violation-id)))
        (asserts!
            (map-insert condition-violations { violation-id: violation-id } {
                product-id: product-id,
                reading-id: reading-id,
                violation-type: "humidity",
                recorded-value: recorded-value,
                expected-range: "humidity-range",
                timestamp: stacks-block-height,
                auto-flagged: true,
            })
            err-already-exists
        )
        (var-set next-violation-id (+ violation-id u1))
        (ok true)
    )
)

(define-read-only (get-product-conditions (product-id uint))
    (map-get? product-conditions { product-id: product-id })
)

(define-read-only (get-condition-reading (reading-id uint))
    (map-get? condition-readings { reading-id: reading-id })
)

(define-read-only (get-condition-violation (violation-id uint))
    (map-get? condition-violations { violation-id: violation-id })
)

(define-read-only (check-current-conditions
        (product-id uint)
        (temperature int)
        (humidity uint)
    )
    (match (map-get? product-conditions { product-id: product-id })
        conditions (ok {
            temp-in-range: (and
                (>= temperature (get min-temp conditions))
                (<= temperature (get max-temp conditions))
            ),
            humidity-in-range: (and
                (>= humidity (get min-humidity conditions))
                (<= humidity (get max-humidity conditions))
            ),
        })
        err-no-conditions-set
    )
)

(define-read-only (get-next-reading-id)
    (var-get next-reading-id)
)

(define-read-only (get-next-violation-id)
    (var-get next-violation-id)
)
