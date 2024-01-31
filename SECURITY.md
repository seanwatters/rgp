# Security

*THIS CODE HAS NOT BEEN AUDITED OR REVIEWED. USE AT YOUR OWN RISK.*

**WARNING:** the AES256 content key encryption implementation may currently be vulnerable to side-channel
timing attacks due to my lack of expertise as it relates to how much (if anything) the timing of the block
allocations reveals about the underlying bytes being allocated. There is *a* way to do this
correctly, it will just need to be reviewed.
