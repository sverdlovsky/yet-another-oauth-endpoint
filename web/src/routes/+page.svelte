<script lang="ts">
  let domain = window.location.hostname.replaceAll('auth.', '');

  let email = '';

  let redirectTimer: ReturnType<typeof setTimeout> | undefined;

  const allowedTlds = [
    'io',
    'ru',
    'me',
    'com',
    'dev',
    'net',
    'org',
    'pro',
    'info',
    'site',
    'online'
  ];

  function isValidEmail(value: string): boolean {
    const normalized = value.trim().toLowerCase();

    if (!normalized.includes('@')) {
      return false;
    }

    const atIndex = normalized.lastIndexOf('@');

    if (atIndex <= 0 || atIndex === normalized.length - 1) {
      return false;
    }

    const emailDomain = normalized.slice(atIndex + 1);

    return allowedTlds.some(
      (tld) => emailDomain.endsWith(`.${tld}`)
    );
  }

  function handleInput(): void {
    if (redirectTimer) {
      clearTimeout(redirectTimer);
    }

    if (!isValidEmail(email)) {
      return;
    }

    redirectTimer = setTimeout(async () => {
      const normalizedEmail = email.trim().toLowerCase();

      const params = new URLSearchParams({
        a: normalizedEmail,
        next: `https://${domain}`,
      });

      try {
        const res = await fetch(
          `/with/email?${params.toString()}`,
          {
            method: 'GET'
          }
        );

        if (!res.ok) {
          return;
        }

        const emailDomain = normalizedEmail
          .split('@')
          .pop();

        if (!emailDomain) {
          return;
        }

        window.location.href = `https://${emailDomain}`;
      } catch (error) {
        console.error('Failed to send email:', error);
      }
    }, 500);
  }
</script>

<main>
  <input
    type="email"
    bind:value={email}
    on:input={handleInput}
    placeholder="your-email@example.com"
    autocomplete="email"
  />
</main>

<style>
  main {
    height: 100vh;
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
  }
</style>
