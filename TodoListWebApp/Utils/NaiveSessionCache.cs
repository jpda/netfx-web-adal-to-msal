using System.Web;
using System.Threading;
using Microsoft.Identity.Client;

namespace TodoListWebApp.Utils
{

    public class NaiveSessionCache
    {
        private static readonly ReaderWriterLockSlim SessionLock = new ReaderWriterLockSlim(LockRecursionPolicy.NoRecursion);
        private readonly string UserObjectId = string.Empty;
        private readonly string CacheId = string.Empty;
        private readonly HttpContext _context;

        public NaiveSessionCache(string userId, HttpContext context)
        {
            UserObjectId = userId;
            CacheId = UserObjectId + "_TokenCache";
            _context = context;
        }

        public void Load(TokenCacheNotificationArgs args)
        {
            SessionLock.EnterReadLock();
            var cacheBytes = (byte[])_context.Session[CacheId];
            args.TokenCache.DeserializeMsalV3(cacheBytes);
            SessionLock.ExitReadLock();
        }

        // happens after the cache has been accessed
        public void Persist(TokenCacheNotificationArgs args)
        {
            if (!args.HasStateChanged) return;
            var cacheBytes = args.TokenCache.SerializeMsalV3();
            SessionLock.EnterWriteLock();
            _context.Session[CacheId] = cacheBytes;
            SessionLock.ExitWriteLock();
        }
    }
}