<?php declare(strict_types=1);

namespace TwoFactorTotp\Entity;

use DateTime;
use Omeka\Entity\AbstractEntity;
use Omeka\Entity\User;

/**
 * A browser the user chose to trust, so it can skip the second step until the
 * trust expires.
 *
 * The cookie is a split token, "selector:validator":
 *
 *  - the selector is stored as-is and is what we look the row up by, so the
 *    lookup is an indexed exact match;
 *  - the validator is stored only as a SHA-256 digest and compared with
 *    hash_equals, so a database leak yields nothing usable and the comparison
 *    cannot be timed.
 *
 * Storing a single token raw would make this table a pile of live session
 * cookies.
 *
 * @Entity
 * @Table(
 *     name="two_factor_totp_trusted_device",
 *     indexes={@Index(name="idx_two_factor_totp_device_expires", columns={"expires"})}
 * )
 * @HasLifecycleCallbacks
 */
class TrustedDevice extends AbstractEntity
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
     * @Column(type="string", length=32, unique=true)
     */
    protected $selector;

    /**
     * @Column(type="string", length=64)
     */
    protected $validatorHash;

    /**
     * @Column(type="datetime")
     */
    protected $expires;

    /**
     * A human-readable hint ("Firefox on Linux") so the user can tell their
     * devices apart in the revoke list.
     *
     * @Column(type="string", length=255, nullable=true)
     */
    protected $label;

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

    public function setSelector(string $selector): self
    {
        $this->selector = $selector;
        return $this;
    }

    public function getSelector(): ?string
    {
        return $this->selector;
    }

    public function setValidatorHash(string $validatorHash): self
    {
        $this->validatorHash = $validatorHash;
        return $this;
    }

    public function getValidatorHash(): ?string
    {
        return $this->validatorHash;
    }

    public function setExpires(DateTime $expires): self
    {
        $this->expires = $expires;
        return $this;
    }

    public function getExpires(): ?DateTime
    {
        return $this->expires;
    }

    public function isExpired(?DateTime $now = null): bool
    {
        return $this->expires <= ($now ?? new DateTime('now'));
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
