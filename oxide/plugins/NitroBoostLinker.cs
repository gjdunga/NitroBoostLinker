// NitroBoostLinker.cs
// MIT License — (c) 2025 Gabriel Dungan (github.com/gjdunga)
//
// Grants the NitroBoost Oxide permission when a linked Discord user is actively
// boosting the guild (premium_since) or has a configured Booster role.
//
// Hard-fails if Image Library, Rust Kits, Custom Auto Kits, or Discord credentials
// are missing. Includes /nitrodiag for live health reporting.
//
// SECURITY MODEL:
//   - Bot token is stored in oxide/config/NitroBoostLinker.json (plaintext).
//     Restrict file-system and RCON/console access on the host.
//   - /nitrodiscordbotlink passes the token as a console argument; Oxide logs all
//     console commands verbatim. Rotate the token if log access is not restricted.
//   - DiscordApiBase is validated to begin with "https://discord.com" at load time
//     to prevent SSRF via a poisoned config file.
//   - HTTP response bodies are NOT written to logs even in debug mode; only the
//     HTTP status code is logged to avoid leaking Discord user PII.
//   - Verification codes are generated with RNGCryptoServiceProvider over an
//     alphabet of length 32 (divides 256 evenly — zero modulo bias).

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Newtonsoft.Json;
using Oxide.Core;
using Oxide.Core.Libraries;
using Oxide.Core.Libraries.Covalence;
using Oxide.Core.Plugins;

namespace Oxide.Plugins
{
    [Info("Nitro Boost Linker", "Gabriel", "1.5.5")]
    [Description("Grants NitroBoost permission when a linked Discord user is boosting or has a Booster role. Hard-fails on missing prerequisites. Includes /nitrodiag and verbose logging.")]
    public class NitroBoostLinker : CovalencePlugin
    {
        // ─────────────────────────────────────────────────────────────────────────
        // CONSTANTS
        // ─────────────────────────────────────────────────────────────────────────

        private const string DisplayVersion = "1.5.5";
        private const string DisplayAuthor  = "Gabriel — MIT License";

        private const string UrlImageLibrary = "https://umod.org/plugins/image-library";
        private const string UrlRustKits     = "https://umod.org/plugins/rust-kits";
        private const string UrlCustomKits   = "https://umod.org/plugins/custom-auto-kits";

        /// <summary>Oxide data file for confirmed Steam-to-Discord links.</summary>
        private const string LinksFile   = "NitroBoostLinker_Links";
        /// <summary>Oxide data file for pending (unverified) link attempts.</summary>
        private const string PendingFile = "NitroBoostLinker_Pending";
        /// <summary>Oxide log file for plugin-specific diagnostic messages.</summary>
        private const string LogFile     = "NitroBoostLinker";

        /// <summary>
        /// Characters used in generated verification codes.
        /// Excludes visually ambiguous characters: 0, O, 1, I.
        /// Length 32 divides 256 evenly — zero modulo bias when used with byte % length.
        /// </summary>
        private const string CodeAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

        /// <summary>
        /// The only origin prefix accepted for DiscordApiBase.
        /// Validated at load time to prevent SSRF via a poisoned config file.
        /// </summary>
        private const string DiscordApiOrigin = "https://discord.com";

        /// <summary>Maximum allowed value for VerificationCodeLength to prevent allocation abuse.</summary>
        private const int MaxCodeLength = 32;

        // ─────────────────────────────────────────────────────────────────────────
        // PLUGIN REFERENCES (null when dependency is not loaded)
        // ─────────────────────────────────────────────────────────────────────────

        /// <summary>Image Library — indirect dependency required by Rust Kits.</summary>
        [PluginReference] private Plugin ImageLibrary;
        /// <summary>Rust Kits — provides the kit grant system.</summary>
        [PluginReference] private Plugin Kits;
        /// <summary>Custom Auto Kits — auto-grants kits based on Oxide permissions.</summary>
        [PluginReference] private Plugin CustomAutoKits;

        // ─────────────────────────────────────────────────────────────────────────
        // HARD-DISABLE STATE
        // ─────────────────────────────────────────────────────────────────────────

        /// <summary>
        /// When true, all player-facing commands are blocked and the reason is logged
        /// and relayed to any admin who attempts to use the plugin.
        /// Set true by default until OnServerInitialized clears prerequisites.
        /// </summary>
        private bool   _hardDisabled       = true;
        private string _hardDisabledReason = "Not initialized";

        /// <summary>
        /// Tracks every bark timer created by StartBarkTimer.
        /// SECURITY: These are destroyed before new timers are created in
        /// ReevaluateHardFailPrereqs, preventing timer accumulation when
        /// OnPluginLoaded / OnPluginUnloaded fire repeatedly on plugin-reload-heavy servers.
        /// </summary>
        private readonly List<Timer> _barkTimers = new List<Timer>();

        // ─────────────────────────────────────────────────────────────────────────
        // CONFIGURATION
        // ─────────────────────────────────────────────────────────────────────────

        private PluginConfig _config;

        private class PluginConfig
        {
            // Discord / guild
            /// <summary>Discord bot token. Keep this secret; do not commit to version control.</summary>
            [JsonProperty("DiscordBotToken")]   public string DiscordBotToken   = string.Empty;
            /// <summary>Numerical ID of the Discord guild to check membership against.</summary>
            [JsonProperty("DiscordGuildId")]    public ulong  DiscordGuildId    = 0;

            // Oxide permission / group
            /// <summary>Oxide permission name granted to qualifying boosters.</summary>
            [JsonProperty("OxidePermissionName")]    public string OxidePermissionName    = "NitroBoost";
            /// <summary>Whether to also add the player to an Oxide group.</summary>
            [JsonProperty("AlsoCreateOxideGroup")]   public bool   AlsoCreateOxideGroup   = true;
            /// <summary>Name of the Oxide group to assign (requires AlsoCreateOxideGroup true).</summary>
            [JsonProperty("OxideGroupName")]         public string OxideGroupName         = "NitroBoost";
            /// <summary>
            /// When true, the plugin only adds players to the group if it already exists.
            /// When false, the group is created automatically at startup.
            /// </summary>
            [JsonProperty("GrantGroupIfExistsOnly")] public bool   GrantGroupIfExistsOnly = true;

            // Boost / role detection
            /// <summary>Treat a non-null premium_since on the guild member as an active boost.</summary>
            [JsonProperty("TreatPremiumSinceAsBoost")] public bool   TreatPremiumSinceAsBoost = true;
            /// <summary>Also check whether the member has a designated Booster role.</summary>
            [JsonProperty("UseBoosterRoleCheck")]      public bool   UseBoosterRoleCheck      = true;
            /// <summary>Discord role ID of the Booster role. Takes precedence over BoosterRoleName.</summary>
            [JsonProperty("BoosterRoleId")]            public ulong  BoosterRoleId            = 0;
            /// <summary>Discord role name to resolve at runtime when BoosterRoleId is 0.</summary>
            [JsonProperty("BoosterRoleName")]          public string BoosterRoleName          = string.Empty;

            // Verification flow
            /// <summary>Length of generated one-time verification codes (1 to 32).</summary>
            [JsonProperty("VerificationCodeLength")]     public int VerificationCodeLength     = 6;
            /// <summary>Seconds before a pending verification code expires.</summary>
            [JsonProperty("VerificationCodeTTLSeconds")] public int VerificationCodeTTLSeconds = 600;

            // Scheduling
            /// <summary>How often in minutes all linked players are re-checked for boost / role status.</summary>
            [JsonProperty("RevalidationIntervalMinutes")] public int RevalidationIntervalMinutes = 60;
            /// <summary>Maximum commands per player per 60-second window. Console / RCON is exempt.</summary>
            [JsonProperty("RateLimitPerPlayerPerMinute")] public int RateLimitPerPlayerPerMinute = 6;

            // Discord API
            /// <summary>
            /// Discord REST API base URL. Must start with "https://discord.com".
            /// SECURITY: The plugin validates this prefix at load time to prevent SSRF.
            /// Do not change unless Discord updates their API version.
            /// </summary>
            [JsonProperty("DiscordApiBase")]     public string DiscordApiBase     = "https://discord.com/api/v10";
            /// <summary>HTTP timeout in seconds for all Discord API calls.</summary>
            [JsonProperty("HttpTimeoutSeconds")] public int    HttpTimeoutSeconds = 15;

            // DM template
            /// <summary>
            /// Template for the verification DM sent to the Discord user.
            /// {CODE} is replaced with the generated one-time code.
            /// </summary>
            [JsonProperty("SendDMTemplate")]
            public string SendDMTemplate =
                "Your Rust verification code is: **{CODE}**\n" +
                "Return to the server and run: `/nitroverify {CODE}`";

            // Diagnostics
            /// <summary>
            /// When true, HTTP error status codes are written to the log file.
            /// Response bodies are NEVER logged regardless of this setting to protect Discord user PII.
            /// </summary>
            [JsonProperty("DebugLogging")] public bool DebugLogging = false;

            // Dependency name aliases
            // These arrays let the plugin find dependencies even when plugin authors
            // vary the display name. All entries are probed via plugins.Find().
            [JsonProperty("ImageLibraryPluginNames")]
            public string[] ImageLibraryPluginNames = { "ImageLibrary", "Image Library", "image-library" };
            [JsonProperty("RustKitsPluginNames")]
            public string[] RustKitsPluginNames = { "Kits", "Rust Kits", "rust-kits" };
            [JsonProperty("CustomAutoKitsPluginNames")]
            public string[] CustomAutoKitsPluginNames = { "Custom Auto Kits", "CustomAutoKits", "custom-auto-kits" };
        }

        protected override void LoadDefaultConfig()
        {
            LogWarning("Generating default configuration file...");
            _config = new PluginConfig();
            SaveConfigTyped();
        }

        private void LoadConfigTyped()
        {
            try
            {
                _config = Config.ReadObject<PluginConfig>();
                if (_config == null) throw new Exception("Config deserialized as null.");
                NormalizeConfig();
            }
            catch (Exception e)
            {
                LogWarning($"Config invalid ({e.Message}); regenerating defaults.");
                LoadDefaultConfig();
            }
        }

        /// <summary>
        /// Clamps or corrects config values that could cause runtime problems if set to
        /// extreme values in the JSON file.
        ///
        /// SECURITY: DiscordApiBase is validated to begin with the Discord origin to prevent
        /// SSRF. A server operator with write access to the config file cannot redirect the
        /// plugin's HTTP calls to internal network addresses.
        /// </summary>
        private void NormalizeConfig()
        {
            if (string.IsNullOrWhiteSpace(_config.OxidePermissionName))
                _config.OxidePermissionName = "NitroBoost";

            if (string.IsNullOrWhiteSpace(_config.OxideGroupName))
                _config.OxideGroupName = "NitroBoost";

            _config.VerificationCodeLength = Math.Max(4, Math.Min(MaxCodeLength, _config.VerificationCodeLength));
            _config.VerificationCodeTTLSeconds   = Math.Max(60, _config.VerificationCodeTTLSeconds);
            _config.RevalidationIntervalMinutes  = Math.Max(5, _config.RevalidationIntervalMinutes);
            _config.RateLimitPerPlayerPerMinute  = Math.Max(1, _config.RateLimitPerPlayerPerMinute);
            _config.HttpTimeoutSeconds           = Math.Max(5, Math.Min(60, _config.HttpTimeoutSeconds));

            if (string.IsNullOrWhiteSpace(_config.DiscordApiBase))
                _config.DiscordApiBase = "https://discord.com/api/v10";

            if (!_config.DiscordApiBase.StartsWith(DiscordApiOrigin, StringComparison.OrdinalIgnoreCase))
            {
                LogWarning($"DiscordApiBase '{_config.DiscordApiBase}' does not start with '{DiscordApiOrigin}'. " +
                           "Resetting to default to prevent SSRF.");
                _config.DiscordApiBase = "https://discord.com/api/v10";
            }
        }

        private void SaveConfigTyped() => Config.WriteObject(_config, true);

        // ─────────────────────────────────────────────────────────────────────────
        // LOCALIZATION
        // ─────────────────────────────────────────────────────────────────────────

        /// <summary>
        /// Keys for all player-facing messages. All values default to English.
        /// Translators: create oxide/lang/{locale}/NitroBoostLinker.json with these keys.
        /// </summary>
        private static class Msg
        {
            public const string HelpText            = "HelpText";
            public const string HardDisabledNotice  = "HardDisabledNotice";
            public const string UsageNitroLink      = "UsageNitroLink";
            public const string InvalidDiscordId    = "InvalidDiscordId";
            public const string AlreadyLinked       = "AlreadyLinked";
            public const string DmFailed            = "DmFailed";
            public const string DmSent              = "DmSent";
            public const string UsageNitroVerify    = "UsageNitroVerify";
            public const string InvalidCode         = "InvalidCode";
            public const string CodeOwnerMismatch   = "CodeOwnerMismatch";
            public const string CodeExpired         = "CodeExpired";
            public const string ApiError            = "ApiError";
            public const string StatusLinked        = "StatusLinked";
            public const string StatusNotLinked     = "StatusNotLinked";
            public const string AdminOnly           = "AdminOnly";
            public const string PlayerNotFound      = "PlayerNotFound";
            public const string ResyncSuccess       = "ResyncSuccess";
            public const string ResyncFailed        = "ResyncFailed";
            public const string ResyncQueued        = "ResyncQueued";
            public const string UsageBotLink        = "UsageBotLink";
            public const string BadGuildId          = "BadGuildId";
            public const string BotLinkFailed       = "BotLinkFailed";
            public const string BotLinkSaved        = "BotLinkSaved";
            public const string BotLinkStillOff     = "BotLinkStillOff";
            public const string BotLinkEnabled      = "BotLinkEnabled";
            public const string RateLimit           = "RateLimit";
            public const string QualifiedBoost      = "QualifiedBoost";
            public const string QualifiedRole       = "QualifiedRole";
            public const string NotQualified        = "NotQualified";
            public const string TokenWarning        = "TokenWarning";
        }

        protected override void LoadDefaultMessages()
        {
            lang.RegisterMessages(new Dictionary<string, string>
            {
                [Msg.HelpText] =
                    "--- Nitro Boost Linker v{version} ---\n" +
                    "Author: {author}\n\n" +
                    "Required plugins:\n" +
                    "  Image Library    {urlImageLib}\n" +
                    "  Rust Kits        {urlKits}\n" +
                    "  Custom Auto Kits {urlCustomKits}\n\n" +
                    "Steps:\n" +
                    "  1) Discord: Settings > Advanced > Developer Mode ON\n" +
                    "     Right-click your avatar > Copy User ID\n" +
                    "  2) /nitrolink <DiscordUserID>\n" +
                    "  3) Check DM from bot for your code\n" +
                    "  4) /nitroverify <CODE>\n\n" +
                    "VIP granted when:\n" +
                    "  - You are actively boosting the guild (premium_since), OR\n" +
                    "  - You have the configured Booster role\n\n" +
                    "Check status: /nitrostatus",

                [Msg.HardDisabledNotice]  = "[DISABLED] {reason}",
                [Msg.UsageNitroLink]      = "Usage: /nitrolink <DiscordUserID>  |  /nitrolink help",
                [Msg.InvalidDiscordId]    = "Invalid Discord User ID — must be a non-zero number.",
                [Msg.AlreadyLinked]       = "Already linked to Discord ID {discordId}. Ask an admin to /nitroresync if your boost status changed.",
                [Msg.DmFailed]            = "Could not DM that Discord user. Verify the ID and ensure the user allows DMs from server members and bots.",
                [Msg.DmSent]             = "Verification code sent via DM to {discordId}. Run /nitroverify <CODE> within {minutes} minute(s).",
                [Msg.UsageNitroVerify]    = "Usage: /nitroverify <CODE>",
                [Msg.InvalidCode]         = "Invalid or expired code. Run /nitrolink <DiscordUserID> again.",
                [Msg.CodeOwnerMismatch]   = "This code does not belong to your account.",
                [Msg.CodeExpired]         = "Code expired. Run /nitrolink <DiscordUserID> again.",
                [Msg.ApiError]            = "Could not verify guild status right now. Try again in a moment.",
                [Msg.StatusLinked]        =
                    "Discord ID   : {discordId}\n" +
                    "Boost/Role   : {boosting}\n" +
                    "Premium Since: {premiumSince}\n" +
                    "Last Checked : {lastChecked}",
                [Msg.StatusNotLinked]     = "Not linked. Run /nitrolink help to get started.",
                [Msg.AdminOnly]           = "Admin or console only.",
                [Msg.PlayerNotFound]      = "Player not found.",
                [Msg.ResyncSuccess]       = "Resynced {name}.",
                [Msg.ResyncFailed]        = "Resync failed for {name} (no link record or API error).",
                [Msg.ResyncQueued]        = "Queued resync for {count} linked player(s).",
                [Msg.UsageBotLink]        = "Usage: /nitrodiscordbotlink <BotToken> <GuildId> [BoosterRoleId|RoleName]",
                [Msg.BadGuildId]          = "GuildId must be a non-zero integer.",
                [Msg.BotLinkFailed]       = "Discord validation failed. Verify the bot token is correct, the bot is in the guild, and the guild ID is right.",
                [Msg.BotLinkSaved]        = "Discord credentials saved and validated. GuildId={guildId}.",
                [Msg.BotLinkStillOff]     = "Still disabled: {reason}",
                [Msg.BotLinkEnabled]      = "Plugin is now ENABLED.",
                [Msg.RateLimit]           = "You are sending commands too quickly. Try again in a moment.",
                [Msg.QualifiedBoost]      = "Linked! Nitro boost detected — {perm} permission granted.",
                [Msg.QualifiedRole]       = "Linked! Booster role detected — {perm} permission granted.",
                [Msg.NotQualified]        = "Linked, but no active Nitro boost or Booster role found. The permission will be granted automatically on the next re-check.",
                [Msg.TokenWarning]        = "[NitroBoostLinker] WARNING: Bot token set via command — visible in server console log. Rotate this token if console access is not restricted to trusted admins.",
            }, this, "en");
        }

        /// <summary>Returns a localized message string for the given player.</summary>
        private string GetMsg(string key, string playerId, params object[] args)
        {
            string msg = lang.GetMessage(key, this, playerId);
            try   { return args.Length > 0 ? string.Format(msg, args) : msg; }
            catch { return msg; }
        }

        // ─────────────────────────────────────────────────────────────────────────
        // DATA MODELS
        // ─────────────────────────────────────────────────────────────────────────

        /// <summary>Persisted record for a confirmed Steam-to-Discord link.</summary>
        private class LinkRecord
        {
            [JsonProperty("SteamId")]              public string    SteamId;
            [JsonProperty("DiscordUserId")]         public ulong     DiscordUserId;
            [JsonProperty("LinkedAtUtc")]           public DateTime  LinkedAtUtc;
            [JsonProperty("LastVerifiedUtc")]       public DateTime  LastVerifiedUtc;
            [JsonProperty("IsBoosting")]            public bool      IsBoosting;
            [JsonProperty("LastKnownPremiumSince")] public DateTime? LastKnownPremiumSince;

            /// <summary>Returns true if the record has the minimum required fields populated.</summary>
            public bool IsValid() => !string.IsNullOrEmpty(SteamId) && DiscordUserId != 0;
        }

        /// <summary>Transient record for a pending (unverified) link attempt.</summary>
        private class PendingRecord
        {
            [JsonProperty("SteamId")]       public string   SteamId;
            [JsonProperty("DiscordUserId")] public ulong    DiscordUserId;
            [JsonProperty("Code")]          public string   Code;
            [JsonProperty("ExpiresUtc")]    public DateTime ExpiresUtc;
            [JsonProperty("CreatedUtc")]    public DateTime CreatedUtc;

            /// <summary>Returns true if the record has the minimum required fields populated.</summary>
            public bool IsValid() =>
                !string.IsNullOrEmpty(SteamId)
                && DiscordUserId != 0
                && !string.IsNullOrEmpty(Code);
        }

        // Confirmed links: SteamId -> LinkRecord
        private Dictionary<string, LinkRecord>    _linked         = new Dictionary<string, LinkRecord>();
        // Pending by SteamId — one active attempt per player; new attempt replaces old
        private Dictionary<string, PendingRecord> _pendingBySteam = new Dictionary<string, PendingRecord>();
        // Pending by code — for O(1) lookup during /nitroverify
        private Dictionary<string, PendingRecord> _pendingByCode  = new Dictionary<string, PendingRecord>();
        // Rate-limit buckets: SteamId -> sliding window of command timestamps
        private readonly Dictionary<string, List<DateTime>> _rate = new Dictionary<string, List<DateTime>>();

        // Booster role ID resolved from name (cached 30 min to reduce API calls)
        private ulong    _boosterRoleIdResolved;
        private DateTime _roleCacheTimeUtc = DateTime.MinValue;

        // ─────────────────────────────────────────────────────────────────────────
        // DISCORD API DTOs
        // ─────────────────────────────────────────────────────────────────────────

        /// <summary>
        /// Result type for CheckMemberBoostOrRole.
        /// Uses a plain private class instead of a C# 7.0 value tuple.
        ///
        /// REASON: Action-typed callbacks with value tuple parameters such as
        /// Action&lt;(bool, DateTime?, bool)?&gt; require System.ValueTuple, which is not
        /// present in the BCL on the .NET target used by Oxide's uMod build servers
        /// (below .NET 4.7, without a NuGet package reference). This causes CS8179:
        /// "Predefined type 'System.ValueTuple' is not defined or imported" at compile time.
        /// A private class compiles cleanly on all Oxide-supported .NET targets.
        /// </summary>
        private class BoostCheckResult
        {
            /// <summary>True when premium_since is non-null and TreatPremiumSinceAsBoost is enabled.</summary>
            public bool      IsPremiumBoosting;
            /// <summary>Raw premium_since value from Discord, or null if the member is not boosting.</summary>
            public DateTime? PremiumSince;
            /// <summary>True when the member has the configured Booster role.</summary>
            public bool      HasBoosterRole;
        }

        private class CreateDMResponse
        {
            [JsonProperty("id")] public string Id;
        }

        private class DiscordUser
        {
            [JsonProperty("id")]          public string Id;
            [JsonProperty("username")]    public string Username;
            [JsonProperty("global_name")] public string GlobalName;
        }

        private class GuildMember
        {
            [JsonProperty("user")]          public DiscordUser  User;
            [JsonProperty("premium_since")] public DateTime?    PremiumSince;
            [JsonProperty("roles")]         public List<string> Roles;
        }

        private class GuildRole
        {
            [JsonProperty("id")]   public string Id;
            [JsonProperty("name")] public string Name;
        }

        // ─────────────────────────────────────────────────────────────────────────
        // LIFECYCLE HOOKS
        // ─────────────────────────────────────────────────────────────────────────

        private void Init()
        {
            LoadConfigTyped();
            RegisterPermissions();
            LoadData();

            AddCovalenceCommand("nitrolink",           nameof(CmdNitroLink));
            AddCovalenceCommand("nitroverify",         nameof(CmdNitroVerify));
            AddCovalenceCommand("nitrostatus",         nameof(CmdNitroStatus));
            AddCovalenceCommand("nitroresync",         nameof(CmdNitroResync));
            AddCovalenceCommand("nitrodiscordbotlink", nameof(CmdNitroDiscordBotLink));
            AddCovalenceCommand("nitrodiag",           nameof(CmdNitroDiag));

            ScheduleRevalidation();
            ScheduleRateCleanup();
        }

        /// <summary>
        /// Delay prerequisite evaluation until all plugins are fully loaded.
        /// Calling in Init risks false negatives for plugins that load after us.
        /// </summary>
        private void OnServerInitialized() => ReevaluateHardFailPrereqs();

        /// <summary>Re-evaluate prerequisites when a tracked dependency loads.</summary>
        private void OnPluginLoaded(Plugin plugin)
        {
            if (plugin != null && MatchesDependency(plugin.Name))
                ReevaluateHardFailPrereqs();
        }

        /// <summary>Re-evaluate prerequisites when a tracked dependency unloads.</summary>
        private void OnPluginUnloaded(Plugin plugin)
        {
            if (plugin != null && MatchesDependency(plugin.Name))
                ReevaluateHardFailPrereqs();
        }

        private void Unload()
        {
            DestroyBarkTimers();
            SaveData();
        }

        // ─────────────────────────────────────────────────────────────────────────
        // PERMISSIONS AND GROUPS
        // ─────────────────────────────────────────────────────────────────────────

        private void RegisterPermissions()
        {
            permission.RegisterPermission(_config.OxidePermissionName, this);

            // Create group at startup only when GrantGroupIfExistsOnly is false
            if (_config.AlsoCreateOxideGroup
                && !_config.GrantGroupIfExistsOnly
                && !permission.GroupExists(_config.OxideGroupName))
            {
                permission.CreateGroup(_config.OxideGroupName, _config.OxideGroupName, 0);
            }
        }

        /// <summary>Grants OxidePermissionName and optionally adds the player to OxideGroupName.</summary>
        private void GrantVip(string steamId)
        {
            if (!permission.UserHasPermission(steamId, _config.OxidePermissionName))
                permission.GrantUserPermission(steamId, _config.OxidePermissionName, this);

            if (!_config.AlsoCreateOxideGroup) return;

            bool groupExists = permission.GroupExists(_config.OxideGroupName);

            if (!groupExists && !_config.GrantGroupIfExistsOnly)
            {
                permission.CreateGroup(_config.OxideGroupName, _config.OxideGroupName, 0);
                groupExists = true;
            }

            if (groupExists)
                permission.AddUserGroup(steamId, _config.OxideGroupName);
        }

        /// <summary>Revokes OxidePermissionName and removes the player from OxideGroupName.</summary>
        private void RevokeVip(string steamId)
        {
            if (permission.UserHasPermission(steamId, _config.OxidePermissionName))
                permission.RevokeUserPermission(steamId, _config.OxidePermissionName);

            if (_config.AlsoCreateOxideGroup && permission.GroupExists(_config.OxideGroupName))
                permission.RemoveUserGroup(steamId, _config.OxideGroupName);
        }

        // ─────────────────────────────────────────────────────────────────────────
        // HARD-FAIL LOGIC
        // ─────────────────────────────────────────────────────────────────────────

        /// <summary>
        /// Checks all prerequisites and either enables the plugin or hard-disables it.
        ///
        /// SECURITY: All existing bark timers are destroyed before any new ones are
        /// created. Without this, every OnPluginLoaded / OnPluginUnloaded cycle that
        /// triggers a hard-disable would accumulate an additional permanent 300-second
        /// timer, causing unbounded memory growth and log flooding on servers that
        /// frequently reload plugins.
        /// </summary>
        private void ReevaluateHardFailPrereqs()
        {
            DestroyBarkTimers();

            bool imageLib = IsImageLibraryPresent();
            bool rustKits = IsRustKitsPresent();
            bool cak      = IsCustomAutoKitsPresent();
            bool discord  = !string.IsNullOrWhiteSpace(_config.DiscordBotToken)
                            && _config.DiscordGuildId != 0;

            if (!imageLib)
            {
                string msg = $"[NitroBoostLinker] HARD-FAIL: Image Library not loaded. Install: {UrlImageLibrary}";
                HardDisable(msg);
                StartBarkTimer(() => !IsImageLibraryPresent(), msg);
                return;
            }
            if (!rustKits)
            {
                string msg = $"[NitroBoostLinker] HARD-FAIL: Rust Kits not loaded. Install: {UrlRustKits}";
                HardDisable(msg);
                StartBarkTimer(() => !IsRustKitsPresent(), msg);
                return;
            }
            if (!cak)
            {
                string msg = $"[NitroBoostLinker] HARD-FAIL: Custom Auto Kits not loaded. Install: {UrlCustomKits}";
                HardDisable(msg);
                StartBarkTimer(() => !IsCustomAutoKitsPresent(), msg);
                return;
            }
            if (!discord)
            {
                string msg = "[NitroBoostLinker] HARD-FAIL: Discord bot token or guild ID not configured. " +
                             "Run: /nitrodiscordbotlink <BotToken> <GuildId> [BoosterRoleId|RoleName]";
                HardDisable(msg);
                StartBarkTimer(
                    () => string.IsNullOrWhiteSpace(_config.DiscordBotToken) || _config.DiscordGuildId == 0,
                    msg
                );
                return;
            }

            if (_hardDisabled)
                Puts("[NitroBoostLinker] All prerequisites satisfied — ENABLED.");

            _hardDisabled       = false;
            _hardDisabledReason = string.Empty;
        }

        private void HardDisable(string reason)
        {
            _hardDisabled       = true;
            _hardDisabledReason = reason;
            LogFailure(reason);
        }

        /// <summary>
        /// Creates a 300-second repeating timer that re-logs the failure message while
        /// the condition is still true. The timer is tracked in _barkTimers.
        /// </summary>
        private void StartBarkTimer(Func<bool> stillFailing, string message)
        {
            Timer t = timer.Every(300f, () =>
            {
                if (_hardDisabled && stillFailing())
                    LogFailure(message);
            });
            _barkTimers.Add(t);
        }

        /// <summary>Destroys and clears all active bark timers.</summary>
        private void DestroyBarkTimers()
        {
            foreach (Timer t in _barkTimers)
            {
                try { t?.Destroy(); } catch { /* ignore if already destroyed */ }
            }
            _barkTimers.Clear();
        }

        /// <summary>
        /// If the plugin is hard-disabled, replies to the player with the reason and
        /// writes to the log. Returns true to signal the caller to abort execution.
        /// </summary>
        private bool BarkIfHardDisabled(IPlayer player)
        {
            if (!_hardDisabled) return false;
            string msg = lang.GetMessage(Msg.HardDisabledNotice, this, player?.Id)
                             .Replace("{reason}", _hardDisabledReason);
            player?.Reply(msg);
            LogFailure(_hardDisabledReason);
            return true;
        }

        /// <summary>
        /// Writes to: Oxide console (PrintError), Oxide global error log,
        /// and oxide/logs/NitroBoostLinker.txt.
        /// </summary>
        private void LogFailure(string message)
        {
            PrintError(message);
            Interface.Oxide.LogError(message);
            LogToFile(LogFile, $"[{DateTime.UtcNow:u}] {message}", this);
        }

        // ─────────────────────────────────────────────────────────────────────────
        // COMMANDS
        // ─────────────────────────────────────────────────────────────────────────

        /// <summary>
        /// /nitrolink [DiscordUserID|help]
        ///
        /// Players: Begin the Discord link flow by sending a DM with a one-time code.
        /// /nitrolink help is always available, even while hard-disabled.
        /// </summary>
        private void CmdNitroLink(IPlayer player, string command, string[] args)
        {
            if (player == null || !player.IsConnected) return;

            if (args.Length == 1 && args[0].Equals("help", StringComparison.OrdinalIgnoreCase))
            {
                string help = lang.GetMessage(Msg.HelpText, this, player.Id)
                    .Replace("{version}",     DisplayVersion)
                    .Replace("{author}",      DisplayAuthor)
                    .Replace("{urlImageLib}", UrlImageLibrary)
                    .Replace("{urlKits}",     UrlRustKits)
                    .Replace("{urlCustomKits}", UrlCustomKits);
                player.Reply(help);

                if (_hardDisabled)
                    player.Reply(lang.GetMessage(Msg.HardDisabledNotice, this, player.Id)
                        .Replace("{reason}", _hardDisabledReason));
                return;
            }

            if (BarkIfHardDisabled(player)) return;
            if (!CheckRate(player))         return;

            if (args.Length != 1)
            {
                player.Reply(lang.GetMessage(Msg.UsageNitroLink, this, player.Id));
                return;
            }

            if (!ulong.TryParse(args[0], out ulong discordUserId) || discordUserId == 0)
            {
                player.Reply(lang.GetMessage(Msg.InvalidDiscordId, this, player.Id));
                return;
            }

            string steamId = player.Id;

            if (_linked.TryGetValue(steamId, out LinkRecord existing))
            {
                player.Reply(lang.GetMessage(Msg.AlreadyLinked, this, player.Id)
                    .Replace("{discordId}", existing.DiscordUserId.ToString()));
                return;
            }

            string   code = GenerateUniqueCode(_config.VerificationCodeLength);
            DateTime now  = DateTime.UtcNow;

            // Remove any stale pending attempt for this player before inserting new one
            if (_pendingBySteam.TryGetValue(steamId, out PendingRecord old))
                _pendingByCode.Remove(old.Code);

            var pending = new PendingRecord
            {
                SteamId       = steamId,
                DiscordUserId = discordUserId,
                Code          = code,
                CreatedUtc    = now,
                ExpiresUtc    = now.AddSeconds(_config.VerificationCodeTTLSeconds)
            };

            _pendingBySteam[steamId] = pending;
            _pendingByCode[code]     = pending;
            SaveData();

            SendVerificationDM(discordUserId, code, ok =>
            {
                if (!ok)
                {
                    _pendingBySteam.Remove(steamId);
                    _pendingByCode.Remove(code);
                    SaveData();
                    player.Reply(lang.GetMessage(Msg.DmFailed, this, player.Id));
                    return;
                }

                int minutes = Math.Max(1, _config.VerificationCodeTTLSeconds / 60);
                player.Reply(lang.GetMessage(Msg.DmSent, this, player.Id)
                    .Replace("{discordId}", discordUserId.ToString())
                    .Replace("{minutes}",   minutes.ToString()));
            });
        }

        /// <summary>
        /// /nitroverify CODE
        ///
        /// Players: Submit the one-time code received via Discord DM to complete linking.
        /// Code is upper-cased before lookup for fault tolerance.
        /// Ownership is verified: a player cannot use another player's code.
        /// </summary>
        private void CmdNitroVerify(IPlayer player, string command, string[] args)
        {
            if (player == null || !player.IsConnected) return;
            if (BarkIfHardDisabled(player)) return;
            if (!CheckRate(player))         return;

            if (args.Length != 1)
            {
                player.Reply(lang.GetMessage(Msg.UsageNitroVerify, this, player.Id));
                return;
            }

            string code = args[0].Trim().ToUpperInvariant();

            if (!_pendingByCode.TryGetValue(code, out PendingRecord pending))
            {
                player.Reply(lang.GetMessage(Msg.InvalidCode, this, player.Id));
                return;
            }

            // Ownership check: prevent one player from using another's code
            if (!string.Equals(pending.SteamId, player.Id, StringComparison.Ordinal))
            {
                player.Reply(lang.GetMessage(Msg.CodeOwnerMismatch, this, player.Id));
                return;
            }

            if (DateTime.UtcNow > pending.ExpiresUtc)
            {
                CleanupPending(pending);
                player.Reply(lang.GetMessage(Msg.CodeExpired, this, player.Id));
                return;
            }

            CheckMemberBoostOrRole(pending.DiscordUserId, result =>
            {
                if (result == null)
                {
                    player.Reply(lang.GetMessage(Msg.ApiError, this, player.Id));
                    return;
                }

                bool qualifies = result.IsPremiumBoosting || result.HasBoosterRole;
                DateTime ts    = DateTime.UtcNow;

                _linked[player.Id] = new LinkRecord
                {
                    SteamId               = player.Id,
                    DiscordUserId         = pending.DiscordUserId,
                    LinkedAtUtc           = ts,
                    LastVerifiedUtc       = ts,
                    IsBoosting            = qualifies,
                    LastKnownPremiumSince = result.PremiumSince
                };

                CleanupPending(pending);
                SaveData();

                if (qualifies)
                {
                    GrantVip(player.Id);
                    string msgKey = result.IsPremiumBoosting ? Msg.QualifiedBoost : Msg.QualifiedRole;
                    player.Reply(lang.GetMessage(msgKey, this, player.Id)
                        .Replace("{perm}", _config.OxidePermissionName));
                }
                else
                {
                    player.Reply(lang.GetMessage(Msg.NotQualified, this, player.Id));
                }
            });
        }

        /// <summary>
        /// /nitrostatus
        ///
        /// Players: Display current link and boost status.
        /// Prepends the disabled reason when hard-disabled.
        /// </summary>
        private void CmdNitroStatus(IPlayer player, string command, string[] args)
        {
            if (player == null || !player.IsConnected) return;

            string prefix = _hardDisabled
                ? lang.GetMessage(Msg.HardDisabledNotice, this, player.Id)
                      .Replace("{reason}", _hardDisabledReason) + "\n"
                : string.Empty;

            if (_linked.TryGetValue(player.Id, out LinkRecord link))
            {
                player.Reply(prefix + lang.GetMessage(Msg.StatusLinked, this, player.Id)
                    .Replace("{discordId}",    link.DiscordUserId.ToString())
                    .Replace("{boosting}",     link.IsBoosting ? "Yes" : "No")
                    .Replace("{premiumSince}", link.LastKnownPremiumSince?.ToString("u") ?? "n/a")
                    .Replace("{lastChecked}",  link.LastVerifiedUtc.ToString("u")));
            }
            else
            {
                player.Reply(prefix + lang.GetMessage(Msg.StatusNotLinked, this, player.Id));
            }
        }

        /// <summary>
        /// /nitroresync [player]
        ///
        /// Admin / console: Force re-check of boost / role status.
        /// With argument: re-checks one named / ID player.
        /// Without argument: queues re-check for all linked players.
        /// </summary>
        private void CmdNitroResync(IPlayer player, string command, string[] args)
        {
            if (player != null && !player.IsServer && !player.IsAdmin)
            {
                player.Reply(lang.GetMessage(Msg.AdminOnly, this, player.Id));
                return;
            }

            if (BarkIfHardDisabled(player)) return;

            if (args.Length == 1)
            {
                IPlayer target = FindPlayer(args[0]);
                if (target == null)
                {
                    player?.Reply(lang.GetMessage(Msg.PlayerNotFound, this, player?.Id));
                    return;
                }

                ResyncPlayer(target.Id, ok =>
                    player?.Reply(ok
                        ? lang.GetMessage(Msg.ResyncSuccess, this, player?.Id)
                              .Replace("{name}", target.Name)
                        : lang.GetMessage(Msg.ResyncFailed, this, player?.Id)
                              .Replace("{name}", target.Name)));
                return;
            }

            int count = 0;
            foreach (KeyValuePair<string, LinkRecord> kv in _linked)
            {
                ResyncPlayer(kv.Key, null);
                count++;
            }
            player?.Reply(lang.GetMessage(Msg.ResyncQueued, this, player?.Id)
                .Replace("{count}", count.ToString()));
        }

        /// <summary>
        /// /nitrodiscordbotlink BotToken GuildId [BoosterRoleId|RoleName]
        ///
        /// Admin / console / RCON: Configure Discord credentials at runtime without editing files.
        ///
        /// SECURITY NOTE: The bot token is passed as a command argument. Oxide logs all console
        /// commands verbatim. Restrict console and RCON access to prevent token exposure.
        /// Rotate the token if console logs may have been viewed by unauthorized parties.
        /// </summary>
        private void CmdNitroDiscordBotLink(IPlayer player, string command, string[] args)
        {
            if (player != null && !player.IsServer && !player.IsAdmin)
            {
                player?.Reply(lang.GetMessage(Msg.AdminOnly, this, player?.Id));
                return;
            }

            if (args.Length < 2)
            {
                player?.Reply(lang.GetMessage(Msg.UsageBotLink, this, player?.Id));
                return;
            }

            if (!ulong.TryParse(args[1], out ulong newGuildId) || newGuildId == 0)
            {
                player?.Reply(lang.GetMessage(Msg.BadGuildId, this, player?.Id));
                return;
            }

            // Security warning: token will appear in Oxide's server console log verbatim
            Puts(lang.GetMessage(Msg.TokenWarning, this, null));

            _config.DiscordBotToken = args[0];
            _config.DiscordGuildId  = newGuildId;

            if (args.Length >= 3)
            {
                if (ulong.TryParse(args[2], out ulong roleId) && roleId != 0)
                {
                    _config.BoosterRoleId   = roleId;
                    _config.BoosterRoleName = string.Empty;
                }
                else
                {
                    _config.BoosterRoleName = args[2];
                    _config.BoosterRoleId   = 0;
                }
            }

            ValidateDiscordCredentials(ok =>
            {
                if (!ok)
                {
                    player?.Reply(lang.GetMessage(Msg.BotLinkFailed, this, player?.Id));
                    LogFailure("[NitroBoostLinker] Discord validation failed during /nitrodiscordbotlink.");
                    return;
                }

                SaveConfigTyped();
                player?.Reply(lang.GetMessage(Msg.BotLinkSaved, this, player?.Id)
                    .Replace("{guildId}", _config.DiscordGuildId.ToString()));
                Puts("[NitroBoostLinker] Discord credentials validated and saved.");

                ReevaluateHardFailPrereqs();

                player?.Reply(_hardDisabled
                    ? lang.GetMessage(Msg.BotLinkStillOff, this, player?.Id)
                          .Replace("{reason}", _hardDisabledReason)
                    : lang.GetMessage(Msg.BotLinkEnabled, this, player?.Id));
            });
        }

        /// <summary>
        /// /nitrodiag
        ///
        /// Admin / console / RCON: Print a full health / status report to chat, console,
        /// and oxide/logs/NitroBoostLinker.txt.
        /// </summary>
        private void CmdNitroDiag(IPlayer player, string command, string[] args)
        {
            if (player != null && !player.IsServer && !player.IsAdmin)
            {
                player?.Reply(lang.GetMessage(Msg.AdminOnly, this, player?.Id));
                return;
            }

            bool discordOk = !string.IsNullOrWhiteSpace(_config.DiscordBotToken) && _config.DiscordGuildId != 0;

            var sb = new StringBuilder();
            sb.AppendLine($"--- NitroBoostLinker v{DisplayVersion} Diagnostics ---");
            sb.AppendLine($"Status        : {(_hardDisabled ? $"DISABLED — {_hardDisabledReason}" : "ENABLED")}");
            sb.AppendLine($"Image Library : {(IsImageLibraryPresent()   ? "OK" : "MISSING")}");
            sb.AppendLine($"Rust Kits     : {(IsRustKitsPresent()       ? "OK" : "MISSING")}");
            sb.AppendLine($"Custom Auto K : {(IsCustomAutoKitsPresent() ? "OK" : "MISSING")}");
            sb.AppendLine($"Discord cfg   : {(discordOk                 ? "OK" : "MISSING")}");
            sb.AppendLine($"API base      : {_config.DiscordApiBase}");
            sb.AppendLine(
                $"Booster Role  : ID={(_config.BoosterRoleId != 0 ? _config.BoosterRoleId.ToString() : "n/a")} " +
                $"Name={(_config.BoosterRoleName ?? "n/a")}"
            );
            sb.AppendLine($"Permission    : {_config.OxidePermissionName}  Group: {_config.OxideGroupName}");
            sb.AppendLine($"Revalidation  : every {_config.RevalidationIntervalMinutes} min");
            sb.AppendLine($"Rate limit    : {_config.RateLimitPerPlayerPerMinute}/min per player");
            sb.AppendLine($"Linked count  : {_linked.Count}");
            sb.AppendLine($"Pending count : {_pendingBySteam.Count}");

            string msg = sb.ToString();
            player?.Reply(msg);
            Puts(StripRichText(msg));
            LogToFile(LogFile, $"[{DateTime.UtcNow:u}] DIAG:\n{StripRichText(msg)}", this);
        }

        // ─────────────────────────────────────────────────────────────────────────
        // BOOST / ROLE VERIFICATION AND SCHEDULING
        // ─────────────────────────────────────────────────────────────────────────

        /// <summary>
        /// Re-checks Discord boost / role status for one linked player and grants or revokes VIP.
        /// Calls done(true) on success, done(false) if the player has no link record or the API fails.
        /// </summary>
        private void ResyncPlayer(string steamId, Action<bool> done)
        {
            if (_hardDisabled || !_linked.TryGetValue(steamId, out LinkRecord link))
            {
                done?.Invoke(false);
                return;
            }

            CheckMemberBoostOrRole(link.DiscordUserId, result =>
            {
                if (result == null) { done?.Invoke(false); return; }

                link.LastVerifiedUtc       = DateTime.UtcNow;
                link.IsBoosting            = result.IsPremiumBoosting || result.HasBoosterRole;
                link.LastKnownPremiumSince = result.PremiumSince;
                SaveData();

                if (link.IsBoosting) GrantVip(steamId);
                else                 RevokeVip(steamId);

                done?.Invoke(true);
            });
        }

        /// <summary>Schedules periodic revalidation for all linked players.</summary>
        private void ScheduleRevalidation()
        {
            int seconds = Math.Max(60, _config.RevalidationIntervalMinutes * 60);
            timer.Every(seconds, () =>
            {
                if (_hardDisabled) return;
                foreach (KeyValuePair<string, LinkRecord> kv in _linked.ToArray())
                    ResyncPlayer(kv.Key, null);
            });
        }

        /// <summary>
        /// Hourly cleanup of the rate-limit dictionary.
        ///
        /// SECURITY: Without this, _rate grows unbounded as every player who ever connected
        /// leaves a permanent entry, causing memory growth on long-running servers.
        /// Entries are removed when all timestamps in the window are older than 2 minutes.
        /// </summary>
        private void ScheduleRateCleanup()
        {
            timer.Every(3600f, () =>
            {
                DateTime cutoff = DateTime.UtcNow.AddMinutes(-2);
                var stale = _rate
                    .Where(kv => kv.Value.Count == 0 || kv.Value.All(t => t < cutoff))
                    .Select(kv => kv.Key)
                    .ToList();
                foreach (string id in stale)
                    _rate.Remove(id);
            });
        }

        // ─────────────────────────────────────────────────────────────────────────
        // DISCORD REST API
        // ─────────────────────────────────────────────────────────────────────────

        /// <summary>Returns true for HTTP 2xx success codes.</summary>
        private static bool HttpOK(int code) => code >= 200 && code < 300;

        /// <summary>Returns the Authorization header required for all Discord API calls.</summary>
        private Dictionary<string, string> AuthHeaders() =>
            new Dictionary<string, string> { ["Authorization"] = $"Bot {_config.DiscordBotToken}" };

        /// <summary>
        /// Validates bot token (GET /users/@me) and guild membership (GET /guilds/{id}).
        /// Calls cb(true) only if both requests succeed with 2xx.
        /// </summary>
        private void ValidateDiscordCredentials(Action<bool> cb)
        {
            webrequest.Enqueue(
                $"{_config.DiscordApiBase}/users/@me",
                null,
                (s1, _r1) =>
                {
                    if (!HttpOK(s1)) { cb?.Invoke(false); return; }
                    webrequest.Enqueue(
                        $"{_config.DiscordApiBase}/guilds/{_config.DiscordGuildId}",
                        null,
                        (s2, _r2) => cb?.Invoke(HttpOK(s2)),
                        this, RequestMethod.GET, AuthHeaders(), _config.HttpTimeoutSeconds
                    );
                },
                this, RequestMethod.GET, AuthHeaders(), _config.HttpTimeoutSeconds
            );
        }

        /// <summary>
        /// Creates a DM channel with the Discord user then sends the verification code message.
        /// Two sequential Discord API calls: POST /users/@me/channels, then POST /channels/{id}/messages.
        ///
        /// SECURITY: HTTP response bodies are not written to the log even in debug mode.
        /// Only the HTTP status code is logged to avoid leaking Discord user PII.
        /// </summary>
        private void SendVerificationDM(ulong discordUserId, string code, Action<bool> cb)
        {
            if (_hardDisabled) { cb?.Invoke(false); return; }

            var headers = AuthHeaders();
            headers["Content-Type"] = "application/json";

            string dmBody = JsonConvert.SerializeObject(
                new Dictionary<string, string> { ["recipient_id"] = discordUserId.ToString() }
            );

            webrequest.Enqueue(
                $"{_config.DiscordApiBase}/users/@me/channels",
                dmBody,
                (s1, r1) =>
                {
                    if (!HttpOK(s1))
                    {
                        if (_config.DebugLogging)
                            LogFailure($"[NBL] CreateDM HTTP {s1}");
                        cb?.Invoke(false);
                        return;
                    }

                    CreateDMResponse dm = null;
                    try   { dm = JsonConvert.DeserializeObject<CreateDMResponse>(r1); }
                    catch (Exception e)
                    {
                        if (_config.DebugLogging)
                            LogFailure($"[NBL] CreateDM parse error: {e.Message}");
                    }

                    if (string.IsNullOrEmpty(dm?.Id)) { cb?.Invoke(false); return; }

                    string content = _config.SendDMTemplate.Replace("{CODE}", code);
                    string msgBody = JsonConvert.SerializeObject(
                        new Dictionary<string, string> { ["content"] = content }
                    );

                    webrequest.Enqueue(
                        $"{_config.DiscordApiBase}/channels/{dm.Id}/messages",
                        msgBody,
                        (s2, _r2) =>
                        {
                            if (!HttpOK(s2) && _config.DebugLogging)
                                LogFailure($"[NBL] Send DM HTTP {s2}");
                            cb?.Invoke(HttpOK(s2));
                        },
                        this, RequestMethod.POST, headers, _config.HttpTimeoutSeconds
                    );
                },
                this, RequestMethod.POST, headers, _config.HttpTimeoutSeconds
            );
        }

        /// <summary>
        /// Fetches guild member record and checks for Nitro boost (premium_since) and / or Booster role.
        /// Callback receives null on network / parse failure, otherwise a populated BoostCheckResult.
        ///
        /// SECURITY: The member.Roles list is iterated with an early-exit loop; no bound is needed
        /// because it is provided by Discord (trusted third party). Role name comparison is guarded
        /// by ulong.TryParse to prevent injection via a crafted role ID string.
        /// </summary>
        private void CheckMemberBoostOrRole(ulong discordUserId, Action<BoostCheckResult> cb)
        {
            if (_hardDisabled) { cb?.Invoke(null); return; }

            ResolveBoosterRoleIdIfNeeded(() =>
            {
                webrequest.Enqueue(
                    $"{_config.DiscordApiBase}/guilds/{_config.DiscordGuildId}/members/{discordUserId}",
                    null,
                    (status, resp) =>
                    {
                        if (!HttpOK(status))
                        {
                            if (_config.DebugLogging)
                                LogFailure($"[NBL] GET member HTTP {status}");
                            cb?.Invoke(null);
                            return;
                        }

                        try
                        {
                            GuildMember member = JsonConvert.DeserializeObject<GuildMember>(resp);
                            bool premium = _config.TreatPremiumSinceAsBoost && member?.PremiumSince != null;

                            bool roleOk = false;
                            if (_config.UseBoosterRoleCheck)
                            {
                                ulong target = _config.BoosterRoleId != 0
                                    ? _config.BoosterRoleId
                                    : _boosterRoleIdResolved;

                                if (target != 0 && member?.Roles != null)
                                {
                                    foreach (string rid in member.Roles)
                                    {
                                        if (ulong.TryParse(rid, out ulong id) && id == target)
                                        {
                                            roleOk = true;
                                            break;
                                        }
                                    }
                                }
                            }

                            cb?.Invoke(new BoostCheckResult
                            {
                                IsPremiumBoosting = premium,
                                PremiumSince      = member?.PremiumSince,
                                HasBoosterRole    = roleOk
                            });
                        }
                        catch (Exception e)
                        {
                            if (_config.DebugLogging)
                                LogFailure($"[NBL] Member parse error: {e.Message}");
                            cb?.Invoke(null);
                        }
                    },
                    this, RequestMethod.GET, AuthHeaders(), _config.HttpTimeoutSeconds
                );
            });
        }

        /// <summary>
        /// Resolves BoosterRoleName to its Discord role ID via GET /guilds/{id}/roles.
        /// Result is cached for 30 minutes to reduce Discord API call frequency.
        /// Skipped if BoosterRoleId is already configured, role check is disabled,
        /// or no role name is set.
        /// </summary>
        private void ResolveBoosterRoleIdIfNeeded(Action done)
        {
            bool alreadyResolved = _boosterRoleIdResolved != 0
                                   && (DateTime.UtcNow - _roleCacheTimeUtc).TotalMinutes < 30;

            if (!_config.UseBoosterRoleCheck
                || _config.BoosterRoleId != 0
                || string.IsNullOrWhiteSpace(_config.BoosterRoleName)
                || alreadyResolved)
            {
                done?.Invoke();
                return;
            }

            webrequest.Enqueue(
                $"{_config.DiscordApiBase}/guilds/{_config.DiscordGuildId}/roles",
                null,
                (status, resp) =>
                {
                    if (HttpOK(status))
                    {
                        try
                        {
                            var roles = JsonConvert.DeserializeObject<List<GuildRole>>(resp)
                                        ?? new List<GuildRole>();
                            foreach (GuildRole role in roles)
                            {
                                if (string.Equals(role.Name, _config.BoosterRoleName, StringComparison.OrdinalIgnoreCase)
                                    && ulong.TryParse(role.Id, out ulong id))
                                {
                                    _boosterRoleIdResolved = id;
                                    _roleCacheTimeUtc      = DateTime.UtcNow;
                                    break;
                                }
                            }
                        }
                        catch (Exception e)
                        {
                            if (_config.DebugLogging)
                                LogFailure($"[NBL] Roles parse error: {e.Message}");
                        }
                    }
                    else if (_config.DebugLogging)
                    {
                        LogFailure($"[NBL] GET roles HTTP {status}");
                    }

                    done?.Invoke();
                },
                this, RequestMethod.GET, AuthHeaders(), _config.HttpTimeoutSeconds
            );
        }

        // ─────────────────────────────────────────────────────────────────────────
        // DATA PERSISTENCE
        // ─────────────────────────────────────────────────────────────────────────

        private void LoadData()
        {
            var rawLinked = Interface.Oxide.DataFileSystem
                .ReadObject<Dictionary<string, LinkRecord>>(LinksFile)
                ?? new Dictionary<string, LinkRecord>();

            // SECURITY: Validate each record before accepting it; corrupt disk data must not
            // cause NullReferenceExceptions when accessed later in resync or status commands.
            _linked = new Dictionary<string, LinkRecord>();
            foreach (var kv in rawLinked)
            {
                if (kv.Value != null && kv.Value.IsValid())
                    _linked[kv.Key] = kv.Value;
                else
                    LogWarning($"[NBL] Skipped invalid link record for key '{kv.Key}' during load.");
            }

            var pendingList = Interface.Oxide.DataFileSystem
                .ReadObject<List<PendingRecord>>(PendingFile)
                ?? new List<PendingRecord>();

            _pendingBySteam = new Dictionary<string, PendingRecord>();
            _pendingByCode  = new Dictionary<string, PendingRecord>();

            DateTime now = DateTime.UtcNow;
            foreach (PendingRecord p in pendingList)
            {
                if (p == null || !p.IsValid() || p.ExpiresUtc <= now) continue;
                _pendingBySteam[p.SteamId] = p;
                _pendingByCode[p.Code]     = p;
            }
        }

        private void SaveData()
        {
            Interface.Oxide.DataFileSystem.WriteObject(LinksFile,   _linked);
            Interface.Oxide.DataFileSystem.WriteObject(PendingFile, _pendingBySteam.Values.ToList());
        }

        // ─────────────────────────────────────────────────────────────────────────
        // UTILITIES
        // ─────────────────────────────────────────────────────────────────────────

        /// <summary>
        /// Generates a cryptographically random verification code from CodeAlphabet.
        /// CodeAlphabet.Length == 32, which divides 256 evenly — zero modulo bias.
        /// Length is clamped to [4, MaxCodeLength] before use.
        /// </summary>
        private string GenerateCode(int length)
        {
            length = Math.Max(4, Math.Min(MaxCodeLength, length));
            var bytes  = new byte[length];
            var result = new StringBuilder(length);

            using (var rng = new RNGCryptoServiceProvider())
                rng.GetBytes(bytes);

            foreach (byte b in bytes)
                result.Append(CodeAlphabet[b % CodeAlphabet.Length]);

            return result.ToString();
        }

        /// <summary>
        /// Generates a code that is not already present in _pendingByCode.
        ///
        /// SECURITY: Without this check, a duplicate code would overwrite the first player's
        /// entry in _pendingByCode while leaving _pendingBySteam intact, making cleanup
        /// inconsistent and allowing a second player to claim the wrong pending record.
        /// Retries up to 10 times; returns the final result regardless on the 11th attempt
        /// (probability of collision after 10 tries is negligible).
        /// </summary>
        private string GenerateUniqueCode(int length)
        {
            for (int i = 0; i < 10; i++)
            {
                string code = GenerateCode(length);
                if (!_pendingByCode.ContainsKey(code))
                    return code;
            }
            return GenerateCode(length);
        }

        /// <summary>Removes a pending record from both lookup dictionaries and writes to disk.</summary>
        private void CleanupPending(PendingRecord p)
        {
            if (p == null) return;
            _pendingBySteam.Remove(p.SteamId);
            _pendingByCode.Remove(p.Code);
            SaveData();
        }

        /// <summary>
        /// Enforces per-player rate limiting using a 60-second sliding window.
        /// Console / RCON callers (player.IsServer) are exempt.
        /// Old timestamps are purged on every call to keep the list small.
        /// </summary>
        private bool CheckRate(IPlayer player)
        {
            if (player == null || player.IsServer) return true;

            if (!_rate.TryGetValue(player.Id, out List<DateTime> list))
                _rate[player.Id] = list = new List<DateTime>();

            DateTime now = DateTime.UtcNow;
            list.RemoveAll(t => (now - t).TotalSeconds > 60);

            if (list.Count >= _config.RateLimitPerPlayerPerMinute)
            {
                player.Reply(lang.GetMessage(Msg.RateLimit, this, player.Id));
                return false;
            }

            list.Add(now);
            return true;
        }

        /// <summary>
        /// Finds a player by exact SteamId, then partial case-insensitive name match
        /// (connected players only), then falls back to Covalence lookup (includes offline players).
        /// Returns the first match; name matching is first-match only.
        /// </summary>
        private IPlayer FindPlayer(string nameOrId)
        {
            if (string.IsNullOrWhiteSpace(nameOrId)) return null;

            foreach (IPlayer p in players.Connected)
            {
                if (p == null) continue;
                if (p.Id == nameOrId) return p;
                if (!string.IsNullOrEmpty(p.Name)
                    && p.Name.IndexOf(nameOrId, StringComparison.OrdinalIgnoreCase) >= 0)
                    return p;
            }

            return players.FindPlayer(nameOrId);
        }

        private bool IsImageLibraryPresent()
        {
            if (ImageLibrary != null) return true;
            foreach (string n in _config.ImageLibraryPluginNames)
                if (plugins.Find(n) != null) return true;
            return false;
        }

        private bool IsRustKitsPresent()
        {
            if (Kits != null) return true;
            foreach (string n in _config.RustKitsPluginNames)
                if (plugins.Find(n) != null) return true;
            return false;
        }

        private bool IsCustomAutoKitsPresent()
        {
            if (CustomAutoKits != null) return true;
            foreach (string n in _config.CustomAutoKitsPluginNames)
                if (plugins.Find(n) != null) return true;
            return false;
        }

        /// <summary>Returns true if pluginName matches any alias in the dependency name arrays.</summary>
        private bool MatchesDependency(string pluginName)
        {
            if (string.IsNullOrEmpty(pluginName)) return false;
            return _config.ImageLibraryPluginNames.Contains(pluginName)
                || _config.RustKitsPluginNames.Contains(pluginName)
                || _config.CustomAutoKitsPluginNames.Contains(pluginName);
        }

        /// <summary>
        /// Strips Rust / Unity rich-text tags using a regex to handle parameterized forms
        /// such as &lt;color=#FF0000&gt; and &lt;size=14&gt;. Plain string.Replace would
        /// silently pass those tags through into log output.
        /// </summary>
        private static string StripRichText(string s)
        {
            if (string.IsNullOrEmpty(s)) return string.Empty;
            return Regex.Replace(s, @"<\/?(b|i|u|size|color)(=[^>]*)?>", string.Empty,
                                 RegexOptions.IgnoreCase);
        }
    }
}
