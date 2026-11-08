# Signal-family message detection

Lottery and courier categories use signal families instead of fixed, exact
phrase lists. Each active match is included in the report as a heuristic
finding such as `signal:authority_customs`, with the matched words in its
detail. A category is assigned only when its configured combination rule in
`data/seed/scam_categories.json` qualifies.

For these combinations, two distinct strong signals score 25 (Moderate), and
three or more score 50 (High). Signal-family matches by themselves carry no
score. Lottery signals require prize context and a payment, urgent-call, or
link-based action. Courier signals require parcel context, customs/prohibited
context, and an active payment/fee signal. Call pressure, urgency, link use,
prohibited-item language, and arrest/legal threats add corroborating signals.
The report shows both individual matches and the combined signals used for the
score.

Payment terms in clear advisory or completed-payment language (for example,
“no fee due”, “fee waived”, “already paid”, or “included in the order”) are not
treated as an active demand. OTP/security notices that tell people not to share
codes are not treated as credential requests. These are heuristic rules; they
do not establish whether a sender, payment request, or courier notice is real.

KYC checks also report account-verification, restriction/suspension,
verification-link, bank/government-claim, urgency, and unverified-domain
signals. KYC + an account restriction threat + a verification link scores at
least Moderate. An unverified domain with urgency adds 8 points; an unverified
domain paired with a bank/government claim adds 8 more. Domains outside the
small trusted-domain list are described as unverified, not as malicious or
proven unsafe.

Regression coverage includes the three prize/courier false negatives, the new
KYC phishing example, the two-signal Moderate and three-signal High thresholds,
15 prize/courier lookalikes, five bill/bank/OTP hard negatives, and five genuine
KYC/bank lookalikes. The evaluation dataset and frozen test split were not
changed or used for tuning.
