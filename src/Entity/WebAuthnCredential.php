<?php declare(strict_types=1);

namespace TwoFactorTotp\Entity;

use DateTime;
use Omeka\Entity\AbstractEntity;
use Omeka\Entity\User;

/**
 * One registered passkey.
 *
 * Unlike the TOTP enrollment — a @OneToOne, one secret per account — a user has
 * *many* of these: a phone, a laptop, a hardware key. That is the normal way
 * passkeys are used, and losing one should not lock the account.
 *
 * Nothing writes to this table yet; it ships now so the schema change and its
 * migration happen in a single module version bump, because a bump takes the
 * module offline until an administrator runs the upgrade.
 *
 * @Entity
 * @Table(
 *     name="two_factor_totp_webauthn_credential",
 *     indexes={@Index(name="idx_two_factor_totp_webauthn_user", columns={"user_id"})}
 * )
 * @HasLifecycleCallbacks
 */
class WebAuthnCredential extends AbstractEntity
{
    /**
     * @Id
     * @Column(type="integer")
     * @GeneratedValue
     */
    protected $id;

    /**
     * @ManyToOne(targetEntity="Omeka\Entity\User")
     * @JoinColumn(nullable=false, onDelete="CASCADE")
     */
    protected $user;

    /**
     * The credential id, base64url-encoded.
     *
     * Stored as text rather than VARBINARY on purpose: Doctrine's binary type
     * hands back a stream resource on hydration, which is a poor fit for a
     * value that only ever gets compared and handed to JavaScript. The column
     * uses an ascii_bin collation so comparison stays byte-exact and
     * case-sensitive — base64url is case-significant, and a case-insensitive
     * match here would let one credential impersonate another.
     *
     * @Column(type="string", length=255, unique=true, options={"collation"="ascii_bin"})
     */
    protected $credentialId;

    /**
     * The COSE public key, PEM-encoded, as the WebAuthn library returns it.
     *
     * @Column(type="text")
     */
    protected $publicKey;

    /**
     * The authenticator's signature counter.
     *
     * A value that fails to advance can mean the credential has been cloned,
     * so this is kept to be compared on every assertion.
     *
     * @Column(type="bigint", options={"unsigned"=true, "default"=0})
     */
    protected $signCount = 0;

    /**
     * What the user calls it: "YubiKey", "work laptop".
     *
     * @Column(type="string", length=255, nullable=true)
     */
    protected $label;

    /**
     * Comma-separated hints from the browser, e.g. "internal,hybrid".
     *
     * @Column(type="string", length=100, nullable=true)
     */
    protected $transports;

    /**
     * Authenticator model identifier, hex-encoded.
     *
     * @Column(type="string", length=64, nullable=true)
     */
    protected $aaguid;

    /**
     * @Column(type="datetime")
     */
    protected $created;

    /**
     * @Column(type="datetime", nullable=true)
     */
    protected $lastUsedAt;

    public function getId()
    {
        return $this->id;
    }

    public function setUser(User $user): self
    {
        $this->user = $user;
        return $this;
    }

    public function getUser(): ?User
    {
        return $this->user;
    }

    public function setCredentialId(string $credentialId): self
    {
        $this->credentialId = $credentialId;
        return $this;
    }

    public function getCredentialId(): ?string
    {
        return $this->credentialId;
    }

    public function setPublicKey(string $publicKey): self
    {
        $this->publicKey = $publicKey;
        return $this;
    }

    public function getPublicKey(): ?string
    {
        return $this->publicKey;
    }

    public function setSignCount(int $signCount): self
    {
        $this->signCount = $signCount;
        return $this;
    }

    /**
     * Doctrine hands bigint back as a string; callers want an int.
     */
    public function getSignCount(): int
    {
        return (int) $this->signCount;
    }

    public function setLabel(?string $label): self
    {
        $this->label = null === $label ? null : mb_substr($label, 0, 255);
        return $this;
    }

    public function getLabel(): ?string
    {
        return $this->label;
    }

    public function setTransports(?string $transports): self
    {
        $this->transports = null === $transports ? null : mb_substr($transports, 0, 100);
        return $this;
    }

    public function getTransports(): ?string
    {
        return $this->transports;
    }

    public function setAaguid(?string $aaguid): self
    {
        $this->aaguid = $aaguid;
        return $this;
    }

    public function getAaguid(): ?string
    {
        return $this->aaguid;
    }

    public function setCreated(DateTime $created): self
    {
        $this->created = $created;
        return $this;
    }

    public function getCreated(): ?DateTime
    {
        return $this->created;
    }

    public function setLastUsedAt(?DateTime $lastUsedAt): self
    {
        $this->lastUsedAt = $lastUsedAt;
        return $this;
    }

    public function getLastUsedAt(): ?DateTime
    {
        return $this->lastUsedAt;
    }

    /**
     * @PrePersist
     */
    public function prePersist(): void
    {
        if (null === $this->created) {
            $this->created = new DateTime('now');
        }
    }
}
