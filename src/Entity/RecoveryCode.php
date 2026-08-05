<?php declare(strict_types=1);

namespace TwoFactorTotp\Entity;

use DateTime;
use Omeka\Entity\AbstractEntity;
use Omeka\Entity\User;

/**
 * A single-use code that gets an account back in when the second factor itself
 * is unavailable.
 *
 * These belong to the *user*, not to any one factor. They used to live in a
 * JSON column on the TOTP enrollment, which meant an account whose only factor
 * was something else — a passkey, say — had no way back in at all. Keeping them
 * here means the fallback survives whichever factors come and go.
 *
 * Spent codes are kept with a `usedAt` stamp rather than deleted: "a recovery
 * code was used on this account" is exactly the kind of thing worth being able
 * to see afterwards.
 *
 * @Entity
 * @Table(
 *     name="two_factor_totp_recovery_code",
 *     indexes={@Index(name="idx_two_factor_totp_recovery_user", columns={"user_id"})}
 * )
 * @HasLifecycleCallbacks
 */
class RecoveryCode extends AbstractEntity
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
     * A password_hash() of the normalised code — never the code itself.
     *
     * @Column(type="string", length=255)
     */
    protected $codeHash;

    /**
     * @Column(type="datetime")
     */
    protected $created;

    /**
     * Null while the code is still usable.
     *
     * @Column(type="datetime", nullable=true)
     */
    protected $usedAt;

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

    public function setCodeHash(string $codeHash): self
    {
        $this->codeHash = $codeHash;
        return $this;
    }

    public function getCodeHash(): ?string
    {
        return $this->codeHash;
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

    public function setUsedAt(?DateTime $usedAt): self
    {
        $this->usedAt = $usedAt;
        return $this;
    }

    public function getUsedAt(): ?DateTime
    {
        return $this->usedAt;
    }

    public function isUsed(): bool
    {
        return null !== $this->usedAt;
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
