/*
 * Copyright (C) 2026 Blue Networks srl <support+github@bluenetworks.it>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import { Alert, Anchor, Button, Code, Group, Stack, Text } from "@mantine/core";
import { IconAlertTriangle } from "@tabler/icons-react";
import { Component, type ErrorInfo, type ReactNode } from "react";

interface Props {
  children: ReactNode;
}

interface State {
  error: Error | null;
  showDetails: boolean;
}

/**
 * Without this, any render-time exception anywhere in the tree unmounts the
 * entire app to a blank screen with no indication of what happened — the
 * exact failure mode reported against the "add custom feed" modal. Mounted
 * inside Shell around the route <Outlet/>, so one broken view doesn't take
 * the nav and header down with it.
 */
export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null, showDetails: false };

  static getDerivedStateFromError(error: Error): State {
    return { error, showDetails: false };
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
              <>
                <Anchor size="xs" onClick={() => this.setState((s) => ({ showDetails: !s.showDetails }))}>
                  {this.state.showDetails ? "Hide" : "Show"} technical details
                </Anchor>
                {this.state.showDetails && (
                  <Code block style={{ whiteSpace: "pre-wrap", fontSize: 11 }}>
                    {this.state.error.stack}
                  </Code>
                )}
              </>
            )}
            <Group gap="xs">
              <Button size="xs" variant="light" onClick={() => this.setState({ error: null })}>
                Try again
              </Button>
            </Group>
          </Stack>
        </Alert>
      );
    }
    return this.props.children;
  }
}
