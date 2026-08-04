<?php declare(strict_types=1);

namespace TwoFactorTotp\Db\Event\Subscriber;

use Doctrine\Common\EventSubscriber;
use Doctrine\DBAL\Connection;
use Doctrine\ORM\Event\PostFlushEventArgs;
use Doctrine\ORM\Event\PreUpdateEventArgs;
use Doctrine\ORM\Events;
use Laminas\Log\LoggerInterface;
use Omeka\Entity\User;

/**
 * Changing the password revokes every trusted device on that account.
 *
 * People change their password precisely when they think it may be known to
 * someone else. A "remember this device" cookie that survives that is a
 * second factor still in the attacker's pocket, so it goes too.
 *
 * Split across two Doctrine events on purpose: entities may not be removed
 * from within preUpdate, so the change is only *noticed* there and the delete
 * happens in postFlush, by which point the update is committed.
 */
class RevokeDevicesOnPasswordChange implements EventSubscriber
{
    /** @var int[] */
    protected array $pendingUserIds = [];

    /**
     * Either a logger or a callable returning one.
     *
     * A callable is what the delegator passes: resolving Omeka\Logger while the
     * entity manager is still being constructed re-enters that construction
     * (logger -> user-id processor -> authentication service -> entity manager)
     * and recurses until the stack dies. Resolving it on first use instead
     * happens long after every service is built.
     *
     * @var LoggerInterface|callable|null
     */
    protected $logger;

    protected bool $loggerResolved = false;

    /**
     * @param LoggerInterface|callable|null $logger
     */
    public function __construct($logger = null)
    {
        $this->logger = $logger;
        $this->loggerResolved = !is_callable($logger);
    }

    /**
     * Resolve the logger on first use. A logger that cannot be built must not
     * take the password change down with it, so failure means "no logging".
     */
    protected function logger(): ?LoggerInterface
    {
        if (!$this->loggerResolved) {
            $this->loggerResolved = true;
            try {
                $logger = ($this->logger)();
            } catch (\Throwable $e) {
                $logger = null;
            }
            $this->logger = $logger instanceof LoggerInterface ? $logger : null;
        }

        return $this->logger;
    }

    public function getSubscribedEvents(): array
    {
        return [Events::preUpdate, Events::postFlush];
    }

    public function preUpdate(PreUpdateEventArgs $args): void
    {
        $entity = $args->getObject();
        if (!$entity instanceof User) {
            return;
        }

        if (!$args->hasChangedField('passwordHash')) {
            return;
        }

        $id = $entity->getId();
        if ($id) {
            $this->pendingUserIds[] = (int) $id;
        }
    }

    public function postFlush(PostFlushEventArgs $args): void
    {
        if (!$this->pendingUserIds) {
            return;
        }

        $userIds = array_values(array_unique($this->pendingUserIds));
        // Cleared before the delete, so a failure cannot make this retry
        // forever on every subsequent flush.
        $this->pendingUserIds = [];

        try {
            $connection = $args->getEntityManager()->getConnection();
            $deleted = (int) $connection->executeStatement(
                'DELETE FROM two_factor_totp_trusted_device WHERE user_id IN (?)',
                [$userIds],
                [Connection::PARAM_INT_ARRAY]
            );

            if ($deleted && $logger = $this->logger()) {
                $logger->info(sprintf(
                    'TwoFactorTotp: revoked %d trusted device(s) after a password change for user id(s) %s.',
                    $deleted,
                    implode(', ', $userIds)
                ));
            }
        } catch (\Exception $e) {
            // Never let this break the password change itself.
            if ($logger = $this->logger()) {
                $logger->err(sprintf(
                    'TwoFactorTotp: could not revoke trusted devices after a password change: %s',
                    $e->getMessage()
                ));
            }
        }
    }
}
