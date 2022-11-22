package unsealer

import (
	"encoding/json"

	"github.com/go-resty/resty/v2"
	"github.com/pkg/errors"
	"github.com/samber/lo"
)

// vaultRequest handles making a request to the Vault API and recovering the detailed
// error response if the API itself does respond to us.
// It returns the JSON data, whether the response was an error, and any underlying error.
func vaultRequest(resp *resty.Response, err error) (*resty.Response, map[string]interface{}, bool, error) {
	data := map[string]interface{}{}
	if err != nil {
		return resp, data, false, errors.Wrap(err, "error making request")
	}

	// No error, try and unmarshal something
	if err := json.Unmarshal(resp.Body(), &data); err != nil {
		// Got an error unmarshaling - so either junk, or problem with Vault
		return resp, data, false, errors.Wrap(err, "vaultRequest: json.Unmarshal failed")
	}

	// No error - was the request an overall fail from Vault?
	return resp, data, resp.IsError(), nil
}

// errorResponse turns a list of errors from Vault into an actual string list.
func errorResponse(jsonResp map[string]interface{}) []string {
	errorIntfs := jsonResp["errors"].([]interface{})
	return lo.Map(errorIntfs, func(item interface{}, index int) string {
		result, _ := item.(string)
		return result
	})
}
