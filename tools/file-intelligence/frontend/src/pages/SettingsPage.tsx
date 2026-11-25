export default function SettingsPage() {
  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold">Settings</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Configure application preferences
        </p>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        <div className="rounded-lg border border-border bg-card p-4">
          <h3 className="mb-3 font-medium">Scanner Configuration</h3>
          <p className="text-sm text-muted-foreground">
            Thread count, batch size, and exclusion rules
          </p>
        </div>

        <div className="rounded-lg border border-border bg-card p-4">
          <h3 className="mb-3 font-medium">AI Provider</h3>
          <p className="text-sm text-muted-foreground">
            Configure Google Gemini, OpenRouter, or OpenAI
          </p>
        </div>

        <div className="rounded-lg border border-border bg-card p-4">
          <h3 className="mb-3 font-medium">Watch Folders</h3>
          <p className="text-sm text-muted-foreground">
            Configure real-time monitoring folders
          </p>
        </div>

        <div className="rounded-lg border border-border bg-card p-4">
          <h3 className="mb-3 font-medium">Scheduled Scans</h3>
          <p className="text-sm text-muted-foreground">
            Set up automatic recurring scans
          </p>
        </div>
      </div>
    </div>
  );
}
