package runpod

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// DockerConfigJSON represents the structure of .dockerconfigjson
type DockerConfigJSON struct {
	Auths map[string]DockerConfigEntry `json:"auths"`
}

// DockerConfigEntry represents a single registry auth entry
type DockerConfigEntry struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Auth     string `json:"auth"`
}

// RunpodRegistryAuth represents the payload for Runpod registry auth API
type RunpodRegistryAuth struct {
	Name     string `json:"name"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// RunpodRegistryAuthResponse represents the response from Runpod registry auth API
type RunpodRegistryAuthResponse struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username,omitempty"`
	Registry string `json:"registry,omitempty"`
}

// ProcessImagePullSecrets extracts registry credentials from imagePullSecrets and returns a Runpod auth ID
func (c *Client) ProcessImagePullSecrets(pod *v1.Pod, imageName string) (string, error) {
	if len(pod.Spec.ImagePullSecrets) == 0 {
		c.logger.Debug("No imagePullSecrets found for pod", "pod", pod.Name)
		return "", nil
	}

	// Extract registry from image name (e.g., "ghcr.io/user/image:tag" -> "ghcr.io")
	registry := extractRegistryFromImage(imageName)
	if registry == "" {
		c.logger.Debug("Could not extract registry from image", "image", imageName)
		return "", nil
	}

	// Process each imagePullSecret
	var lastErr error
	for _, secretRef := range pod.Spec.ImagePullSecrets {
		authID, err := c.processImagePullSecret(pod.Namespace, secretRef.Name, registry)
		if err != nil {
			lastErr = fmt.Errorf("failed to process imagePullSecret %s: %w", secretRef.Name, err)
			continue
		}
		
		if authID != "" {
			c.logger.Info("Successfully processed imagePullSecret",
				"secret", secretRef.Name,
				"registry", registry,
				"authID", authID)
			return authID, nil
		}
	}
	
	// If we processed secrets but none worked, return the last error
	if lastErr != nil {
		return "", lastErr
	}

	return "", nil
}

// processImagePullSecret processes a single imagePullSecret and creates/retrieves Runpod auth
func (c *Client) processImagePullSecret(namespace, secretName, targetRegistry string) (string, error) {
	// Fetch the secret
	secret, err := c.clientset.CoreV1().Secrets(namespace).Get(
		context.Background(),
		secretName,
		metav1.GetOptions{},
	)
	if err != nil {
		return "", fmt.Errorf("failed to get imagePullSecret %s: %w", secretName, err)
	}

	// Handle different secret types
	switch secret.Type {
	case v1.SecretTypeDockerConfigJson:
		return c.processDockerConfigJsonSecret(secret, targetRegistry)
	case v1.SecretTypeDockercfg:
		return c.processDockerCfgSecret(secret, targetRegistry)
	default:
		return "", fmt.Errorf("unsupported secret type: %s", secret.Type)
	}
}

// processDockerConfigJsonSecret processes kubernetes.io/dockerconfigjson secret
func (c *Client) processDockerConfigJsonSecret(secret *v1.Secret, targetRegistry string) (string, error) {
	configData, exists := secret.Data[v1.DockerConfigJsonKey]
	if !exists {
		return "", fmt.Errorf("missing .dockerconfigjson key in secret")
	}

	var dockerConfig DockerConfigJSON
	if err := json.Unmarshal(configData, &dockerConfig); err != nil {
		return "", fmt.Errorf("failed to parse .dockerconfigjson: %w", err)
	}

	// Find matching registry
	for registry, authEntry := range dockerConfig.Auths {
		if matchesRegistry(registry, targetRegistry) {
			username, password, err := extractCredentials(authEntry)
			if err != nil {
				return "", fmt.Errorf("failed to extract credentials for registry %s: %w", registry, err)
			}

			return c.createRunpodRegistryAuth(registry, username, password)
		}
	}

	return "", nil
}

// processDockerCfgSecret processes kubernetes.io/dockercfg secret (legacy format)
func (c *Client) processDockerCfgSecret(secret *v1.Secret, targetRegistry string) (string, error) {
	// This is similar to dockerconfigjson but without the "auths" wrapper
	configData, exists := secret.Data[v1.DockerConfigKey]
	if !exists {
		return "", fmt.Errorf("missing .dockercfg key in secret")
	}

	var dockerConfig map[string]DockerConfigEntry
	if err := json.Unmarshal(configData, &dockerConfig); err != nil {
		return "", fmt.Errorf("failed to parse .dockercfg: %w", err)
	}

	// Find matching registry
	for registry, authEntry := range dockerConfig {
		if matchesRegistry(registry, targetRegistry) {
			username, password, err := extractCredentials(authEntry)
			if err != nil {
				return "", fmt.Errorf("failed to extract credentials for registry %s: %w", registry, err)
			}

			return c.createRunpodRegistryAuth(registry, username, password)
		}
	}

	return "", nil
}

// extractRegistryFromImage extracts the registry hostname from a container image
func extractRegistryFromImage(image string) string {
	// Handle standard cases:
	// - "ghcr.io/user/image:tag" -> "ghcr.io"
	// - "docker.io/library/nginx:latest" -> "docker.io"
	// - "nginx:latest" -> "" (default Docker Hub)
	
	parts := strings.Split(image, "/")
	if len(parts) >= 2 && strings.Contains(parts[0], ".") {
		return parts[0]
	}
	
	// Default to Docker Hub for images without explicit registry
	if len(parts) == 1 || (len(parts) == 2 && !strings.Contains(parts[0], ".")) {
		return "docker.io"
	}
	
	return ""
}

// matchesRegistry checks if two registry URLs match
func matchesRegistry(secretRegistry, targetRegistry string) bool {
	// Normalize registries (remove https://, trailing slashes, etc.)
	secretReg := normalizeRegistry(secretRegistry)
	targetReg := normalizeRegistry(targetRegistry)
	
	return secretReg == targetReg
}

// normalizeRegistry normalizes a registry URL for comparison
func normalizeRegistry(registry string) string {
	// Remove protocol
	registry = strings.TrimPrefix(registry, "https://")
	registry = strings.TrimPrefix(registry, "http://")
	
	// Remove trailing slash
	registry = strings.TrimSuffix(registry, "/")
	
	// Handle Docker Hub aliases
	if registry == "index.docker.io" || registry == "registry-1.docker.io" {
		return "docker.io"
	}
	
	return registry
}

// extractCredentials extracts username and password from auth entry
func extractCredentials(entry DockerConfigEntry) (string, string, error) {
	// If username and password are directly available
	if entry.Username != "" && entry.Password != "" {
		return entry.Username, entry.Password, nil
	}
	
	// If only base64 auth string is available
	if entry.Auth != "" {
		decoded, err := base64.StdEncoding.DecodeString(entry.Auth)
		if err != nil {
			return "", "", fmt.Errorf("failed to decode auth string: %w", err)
		}
		
		parts := strings.SplitN(string(decoded), ":", 2)
		if len(parts) != 2 {
			return "", "", fmt.Errorf("invalid auth string format")
		}
		
		return parts[0], parts[1], nil
	}
	
	return "", "", fmt.Errorf("no valid credentials found")
}

// createRunpodRegistryAuth creates or retrieves a Runpod registry auth ID
func (c *Client) createRunpodRegistryAuth(registry, username, password string) (string, error) {
	// Create a deterministic name based on registry and username (not password)
	// This allows us to find the auth entry even when password changes
	baseData := fmt.Sprintf("%s:%s", registry, username)
	hash := sha256.Sum256([]byte(baseData))
	authName := fmt.Sprintf("k8s-%x", hash[:8])
	
	c.logger.Debug("Processing registry auth", "registry", registry, "username", username, "authName", authName)
	
	// First, try to get existing auth to compare credentials
	existingAuth, err := c.getRegistryAuth(authName)
	if err != nil {
		c.logger.Debug("No existing registry auth found or error retrieving", "authName", authName, "error", err)
	} else {
		// Compare existing credentials with current ones
		if existingAuth.Username == username {
			c.logger.Debug("Found existing registry auth with matching credentials", "authName", authName, "authID", existingAuth.ID)
			return existingAuth.ID, nil
		} else {
			// Credentials have changed - delete the old one first
			c.logger.Info("Registry auth credentials have changed, recreating", "authName", authName, "oldID", existingAuth.ID)
			if deleteErr := c.deleteRegistryAuth(existingAuth.ID); deleteErr != nil {
				// Log but don't fail - deletion failure is not critical
				c.logger.Warn("Failed to delete old registry auth", "authID", existingAuth.ID, "error", deleteErr)
			}
		}
	}
	
	// Create new registry auth
	authPayload := RunpodRegistryAuth{
		Name:     authName,
		Username: username,
		Password: password,
	}
	
	authID, err := c.saveRegistryAuth(authPayload)
	if err != nil {
		// If creation failed due to existing auth, try to get it
		if strings.Contains(strings.ToLower(err.Error()), "failed to create registry auth") {
			c.logger.Info("Registry auth creation failed, trying to retrieve existing", "authName", authName)
			if existingAuth, getErr := c.getRegistryAuth(authName); getErr == nil {
				return existingAuth.ID, nil
			}
		}
		return "", err
	}
	
	c.logger.Info("Successfully created registry auth", "authName", authName, "authID", authID)
	return authID, nil
}

// getRegistryAuth retrieves an existing registry auth by name
func (c *Client) getRegistryAuth(authName string) (*RunpodRegistryAuthResponse, error) {
	// List all registry auths and find by name
	req, err := http.NewRequest("GET", "https://rest.runpod.io/v1/containerregistryauth", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to list registry auths: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("list registry auths failed with status %d: %s", resp.StatusCode, string(body))
	}
	
	var registryAuths []RunpodRegistryAuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&registryAuths); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	
	// Find by name
	for _, auth := range registryAuths {
		if auth.Name == authName {
			return &auth, nil
		}
	}
	
	return nil, fmt.Errorf("registry auth not found: %s", authName)
}

// deleteRegistryAuth deletes a registry auth by ID
func (c *Client) deleteRegistryAuth(authID string) error {
	url := fmt.Sprintf("https://rest.runpod.io/v1/containerregistryauth/%s", authID)
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create delete request: %w", err)
	}
	
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to delete registry auth: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("delete registry auth failed with status %d: %s", resp.StatusCode, string(body))
	}
	
	c.logger.Info("Successfully deleted registry auth", "authID", authID)
	return nil
}

// saveRegistryAuth saves registry auth to Runpod and returns the auth ID
func (c *Client) saveRegistryAuth(auth RunpodRegistryAuth) (string, error) {
	// Use REST API to create registry auth
	payload, err := json.Marshal(auth)
	if err != nil {
		return "", fmt.Errorf("failed to marshal auth payload: %w", err)
	}
	
	req, err := http.NewRequest("POST", "https://rest.runpod.io/v1/containerregistryauth", strings.NewReader(string(payload)))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to create registry auth: %w", err)
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}
	
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return "", fmt.Errorf("create registry auth failed with status %d: %s", resp.StatusCode, string(body))
	}
	
	var response RunpodRegistryAuthResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}
	
	c.logger.Info("Created new registry auth",
		"authName", auth.Name,
		"authID", response.ID)
	
	return response.ID, nil
}