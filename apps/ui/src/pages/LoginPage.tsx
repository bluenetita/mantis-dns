import { Alert, Button, Card, Center, PasswordInput, Stack, Text, TextInput, Title } from "@mantine/core";
import { useForm } from "@mantine/form";
import { useState } from "react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";
import { BrandMark } from "../components/BrandMark";

export function LoginPage() {
  const { user, login, loading } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const form = useForm({
    initialValues: { email: "", password: "" },
  });

  function safeFrom(): string {
    const raw = (location.state as { from?: string } | null)?.from;
    if (!raw || !raw.startsWith("/") || raw.startsWith("//")) return "/tenants";
    return raw;
  }

  if (!loading && user) {
    return <Navigate to={safeFrom()} replace />;
  }

  const handleSubmit = form.onSubmit(async (values) => {
    setError(null);
    setSubmitting(true);
    try {
      await login(values.email, values.password);
      navigate(safeFrom(), { replace: true });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSubmitting(false);
    }
  });

  return (
    <Center h="100vh">
      <Card withBorder padding="xl" w={380}>
        <Stack align="center" mb="md">
          <BrandMark size={40} />
          <Title order={3}>Mantis-DNS</Title>
          <Text size="sm" c="dimmed">
            Sign in to the control plane
          </Text>
        </Stack>

        <form onSubmit={handleSubmit}>
          <Stack>
            {error && (
              <Alert color="red" title="Sign-in failed">
                {error}
              </Alert>
            )}
            <TextInput
              label="Email"
              placeholder="admin@mantis.local"
              required
              {...form.getInputProps("email")}
            />
            <PasswordInput label="Password" required {...form.getInputProps("password")} />
            <Button type="submit" loading={submitting} fullWidth mt="sm">
              Sign in
            </Button>
          </Stack>
        </form>
      </Card>
    </Center>
  );
}
