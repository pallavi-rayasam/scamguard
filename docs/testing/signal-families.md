# Signal-family message detection

Lottery and courier categories use signal families instead of fixed, exact
phrase lists. Each active match is included in the report as a heuristic
finding such as `signal:authority_customs`, with the matched words in its
detail. A category is assigned only when its configured combination rule in
`data/seed/scam_categories.json` qualifies.

Scores keep the highest weight per indicator, add the distinct indicator
weights, and cap the total at 100. Risk labels use the existing cutoffs: Low
below 25, Moderate from 25, High from 50, and Critical from 75. This score is
an uncalibrated heuristic, not a probability. The 25 cutoff is a cliff, so a
one-point change can flip a label; a strong two-signal combination now has a
30-point floor, while three or more strong signals score 50. Configured
single-signal high-risk families also score 30. An unverified domain plus
urgency raises the current combined score to at least 30, adding only the
points needed if other findings already cross that floor.

Signal-family matches by themselves carry no score. Lottery signals require
prize context and a payment, urgent-call, or link-based action. Courier
signals require parcel context, customs/prohibited context, and an active
payment/fee signal. KYC, digital-arrest, job-fee, utility-disconnection, and
loan-app combinations add their required context and action signals. The
report shows individual matches and combined signals used for the score.

Payment terms in clear advisory or completed-payment language (for example,
“no fee due”, “fee waived”, “already paid”, or “included in the order”) are not
treated as an active demand. OTP/security notices that tell people not to share
codes are not treated as credential requests. These are heuristic rules; they
do not establish whether a sender, payment request, or courier notice is real.

KYC checks also report account-verification, restriction/suspension,
verification-link, bank/government-claim, urgency, and unverified-domain
signals. KYC + an account restriction threat + a verification link scores at
least Moderate. An unverified domain paired with a bank/government claim adds
8 points. Domains outside the small trusted-domain list are described as
unverified, not as malicious or proven unsafe.

Single-signal high-risk families cover direct requests for sensitive identity
or financial details, remote-access app installation, wallet/UPI payments to
unlock or receive something, guaranteed or unusually high returns, refundable
upfront job/loan/prize fees, and urgent money requests after meeting online.
The rules tolerate inserted words and bracketed placeholders such as
`[FAKE-NUMBER]` and `[FAKE-WALLET]`. Negated warnings, normal bank fixed-deposit
rates, and fees explicitly waived, paid, or deducted after loan disbursement
are excluded from active requests.

Regression coverage includes the three prize/courier false negatives, the new
KYC phishing example, four new digital-arrest/job-fee/utility-disconnection/
loan-app scams, the two-signal 30-point and three-signal High thresholds, 15
prize/courier lookalikes, five bill/bank/OTP hard negatives, five genuine
KYC/bank lookalikes, seven v4 false negatives, seven isolated single-signal
tests, and 35 genuine v4 lookalikes (five for each new family). All tested
lookalikes remain Low and uncategorized. The Hinglish example from manual
testing was intentionally omitted; these rules and fixtures cover English
only, so Hinglish detection remains unverified. The evaluation dataset and
frozen test split were not changed or used for tuning.
