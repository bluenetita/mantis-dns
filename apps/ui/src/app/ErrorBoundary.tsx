import { Alert, Button, Code, Stack, Text } from "@mantine/core";
import { IconAlertTriangle } from "@tabler/icons-react";
import { Component, type ErrorInfo, type ReactNode } from "react";

interface Props {
  children: ReactNode;
}

interface State {
  error: Error | null;
}

/**
 * Without this, any render-time exception anywhere in the tree unmounts the
 * entire app to a blank screen with no indication of what happened — the
 * exact failure mode reported against the "add custom feed" modal. Scoping
 * this at the route level (see App.tsx) means one broken view doesn't take
 * down the whole shell, and the actual error is visible without devtools.
 */
export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("Render error caught by ErrorBoundary:", error, info.componentStack);
  }

  render() {
    if (this.state.error) {
      return (
        <Alert icon={<IconAlertTriangle size={18} />} color="red" title="Something broke" m="md">
          <Stack gap="xs">
            <Text size="sm">{this.state.error.message}</Text>
            {this.state.error.stack && (
              <Code block style={{ whiteSpace: "pre-wrap", fontSize: 11 }}>
                {this.state.error.stack}
              </Code>
            )}
            <Button size="xs" variant="light" onClick={() => this.setState({ error: null })}>
              Try again
            </Button>
          </Stack>
        </Alert>
      );
    }
    return this.props.children;
  }
}
