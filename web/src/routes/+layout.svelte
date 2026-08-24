<script lang="ts">
    import "../app.css";

    let domainCut = window.location.hostname.split('.').slice(-2)
    let domain = domainCut.join('.');
    let title = domainCut[0].charAt(0).toUpperCase() + domainCut[0].slice(1);
</script>

<svelte:head>
    <link rel="icon" href="/static/favicon.png"/>
    <title>Auth</title>
</svelte:head>

<slot />
