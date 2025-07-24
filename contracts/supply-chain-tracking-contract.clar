(define-constant contract-owner tx-sender)
(define-constant err-owner-only (err u100))
(define-constant err-not-found (err u101))
(define-constant err-already-exists (err u102))
(define-constant err-unauthorized (err u103))
(define-constant err-invalid-stage (err u104))
(define-constant err-invalid-transfer (err u105))

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

(define-data-var next-product-id uint u1)
(define-data-var next-event-id uint u1)

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
    (match (map-get? authorized-actors { actor: actor })
        auth-data (get authorized auth-data)
        false
    )
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

(define-public (batch-update-stages (updates (list 20
    {
    product-id: uint,
    stage: (string-ascii 50),
    location: (string-ascii 100),
    notes: (string-ascii 200),
})))
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
