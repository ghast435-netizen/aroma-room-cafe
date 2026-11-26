# Aroma Room Cafe — Firestore Security Specification

## 1. Data Invariants
1. Public catalog data (`categories`, `menuItems`, `gallery`, `siteConfig`) is readable by anyone, and writable exclusively by verified administrators.
2. Customer PII collections (`orders`, `reservations`, `contactMessages`) are NEVER publicly listable or readable by unauthenticated users or non-owners.
3. Unauthenticated or customer-created `orders` MUST start in `status == 'submitted'` and `paymentStatus == 'unpaid_offline'`, and MUST atomically create a corresponding non-PII `orderStatuses/{referenceCode}` document via `getAfter` / `existsAfter` verification.
4. Unauthenticated or customer-created `reservations` MUST start in `status == 'pending'`, and MUST atomically create a corresponding non-PII `reservationStatuses/{referenceCode}` document.
5. `orderStatuses` and `reservationStatuses` prohibit `list` queries (`allow list: if false`) to prevent enumeration, allow `get` by exact reference code without exposing PII, and only allow updates by administrators.
6. All `createdAt` / `updatedAt` timestamps MUST equal `request.time`.
7. Admin identity checks enforce `request.auth.token.email_verified == true` when matching the bootstrapped owner email (`bhartii009k@gmail.com`) or verifying `admins/{request.auth.uid}`.

## 2. The "Dirty Dozen" Adversarial Payloads (Must Return PERMISSION_DENIED)
1. **Shadow Field Injection on Order**: `orders/ord1` create with extra field `isPaid: true` -> denied by `hasOnly(...)`.
2. **Pre-Accepted Order Spoof**: `orders/ord1` create with `status: 'accepted'` -> denied by `data.status == 'submitted'`.
3. **Fake Online Payment Spoof**: `orders/ord1` create with `paymentStatus: 'paid'` -> denied by `data.paymentStatus == 'unpaid_offline'`.
4. **Pre-Confirmed Reservation Spoof**: `reservations/res1` create with `status: 'confirmed'` -> denied by `data.status == 'pending'`.
5. **PII Order List Scraping**: Unauthenticated or non-admin `list` on `/orders` -> denied.
6. **PII Reservation Get Leak**: Unauthenticated or non-admin `get` on `/reservations/res1` -> denied.
7. **Status Enumeration Scraping**: Public `list` on `/orderStatuses` or `/reservationStatuses` -> denied (`allow list: if false`).
8. **Self-Assigned Admin Escalation**: Non-admin authenticated user creating `/admins/{uid}` -> denied.
9. **Unverified Admin Email Spoof**: Signed-in user with `email: 'bhartii009k@gmail.com'` and `email_verified: false` attempting admin write -> denied.
10. **Path ID Poisoning**: Creating `/menuItems/<200-char-invalid-id>` -> denied by `isValidId()`.
11. **Menu Price Tampering by Customer**: Non-admin updating `/menuItems/pizza1` price to `1` -> denied.
12. **Client Timestamp Forgery**: Creating `/orders/ord1` with `createdAt: "2020-01-01T00:00:00Z"` instead of `request.time` -> denied.
