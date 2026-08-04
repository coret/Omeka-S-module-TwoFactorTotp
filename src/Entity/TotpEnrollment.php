<?php declare(strict_types=1);

namespace TwoFactorTotp\Entity;

use DateTime;
use Omeka\Entity\AbstractEntity;
use Omeka\Entity\User;

/**
 * One user's TOTP enrollment: their shared secret, their recovery codes and
 * the replay guard.
 *
 * A row exists from the moment enrollment *starts*, but grants nothing until
 * $isConfirmed is true — the user has to prove they can produce a code from
 * the secret before it becomes a factor that can lock them out.
 *
 * @Entity
 * @Table(name="two_factor_totp_enrollment")
 * @HasLifecycleCallbacks
 */
class TotpEnrollment extends AbstractEntity
{
    /**
     * @Id
     * @Column(type="integer")
     * @GeneratedValue
     */
    protected $id;

    /**
     * @OneToOne(targetEntity="Omeka\Entity\User")
     * @JoinColumn(nullable=false, unique=true, onDelete="CASCADE")
     */
    protected $user;

    /**
     * The base32 shared secret.
     *
     * @Column(type="string", length=64)
     */
    protected $secret;

    /**
     * @Column(type="boolean")
     */
    protected $isConfirmed = false;

    /**
     * The highest TOTP counter this user has already spent.
     *
     * This is the replay guard. Without it a code stays valid for the whole
     * remainder of its 30-second step, so one shoulder-surfed or
     * phishing-proxied code can be reused.
     *
     * @Column(type="bigint", nullable=true)
     */
    protected $lastCounter;

    /**
     * password_hash() digests of the single-use recovery codes.
     *
     * Hashed, not encrypted: they are bearer credentials equivalent to a
     * password, and nothing ever needs to read them back.
     *
     * @Column(type="json")
     */
    protected $recoveryCodes = [];

    /**
     * @Column(type="datetime")
     */
    protected $created;

    /**
     * @Column(type="datetime", nullable=true)
     */
    protected $confirmedAt;

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

    public function setSecret(string $secret): self
    {
        $this->secret = $secret;
        return $this;
    }

    public function getSecret(): ?string
    {
        return $this->secret;
    }

    public function setIsConfirmed(bool $isConfirmed): self
    {
        $this->isConfirmed = $isConfirmed;
        return $this;
    }

    public function isConfirmed(): bool
    {
        return (bool) $this->isConfirmed;
    }

    /**
     * Doctrine hands bigint back as a string; callers want an int.
     */
    public function getLastCounter(): ?int
    {
        return null === $this->lastCounter ? null : (int) $this->lastCounter;
    }

    public function setLastCounter(?int $lastCounter): self
    {
        $this->lastCounter = $lastCounter;
        return $this;
    }

    public function getRecoveryCodes(): array
    {
        return is_array($this->recoveryCodes) ? $this->recoveryCodes : [];
    }

    public function setRecoveryCodes(array $recoveryCodes): self
    {
        // Re-index: the column is a JSON list, and a sparse PHP array after an
        // unset() would round-trip as an object instead.
        $this->recoveryCodes = array_values($recoveryCodes);
        return $this;
    }

    public function countRecoveryCodes(): int
    {
        return count($this->getRecoveryCodes());
    }

    public function getCreated(): ?DateTime
    {
        return $this->created;
    }

    public function setConfirmedAt(?DateTime $confirmedAt): self
    {
        $this->confirmedAt = $confirmedAt;
        return $this;
    }

    public function getConfirmedAt(): ?DateTime
    {
        return $this->confirmedAt;
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
