/*
	Copyright 2023 Loophole Labs

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		   http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

// Code generated by swaggo/swag. DO NOT EDIT
package docs

import "github.com/swaggo/swag"

const docTemplateauthAPI = `{
    "schemes": {{ marshal .Schemes }},
    "swagger": "2.0",
    "info": {
        "description": "{{escape .Description}}",
        "title": "{{.Title}}",
        "termsOfService": "https://loopholelabs.io/privacy",
        "contact": {
            "name": "API Support",
            "email": "admin@loopholelabs.io"
        },
        "license": {
            "name": "Apache 2.0",
            "url": "https://www.apache.org/licenses/LICENSE-2.0.html"
        },
        "version": "{{.Version}}"
    },
    "host": "{{.Host}}",
    "basePath": "{{.BasePath}}",
    "paths": {
        "/config": {
            "get": {
                "description": "Config gets the public configuration of the API",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "config"
                ],
                "summary": "Config gets the public configuration of the API",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "type": "array",
                            "items": {
                                "$ref": "#/definitions/models.ConfigResponse"
                            }
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "500": {
                        "description": "Internal Server Error",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        },
        "/device/callback": {
            "post": {
                "description": "DeviceCallback validates the device code and returns the flow identifier",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "device",
                    "callback"
                ],
                "summary": "DeviceCallback validates the device code and returns the flow identifier",
                "parameters": [
                    {
                        "type": "string",
                        "description": "device code",
                        "name": "code",
                        "in": "query",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/models.DeviceCallbackResponse"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "500": {
                        "description": "Internal Server Error",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        },
        "/device/flow": {
            "post": {
                "description": "DeviceFlow starts the device code flow",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "device",
                    "login"
                ],
                "summary": "DeviceFlow starts the device code flow",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/models.DeviceFlowResponse"
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "500": {
                        "description": "Internal Server Error",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        },
        "/device/poll": {
            "post": {
                "description": "DevicePoll polls the device code flow using the user code",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "device",
                    "poll"
                ],
                "summary": "DevicePoll polls the device code flow using the user code",
                "parameters": [
                    {
                        "type": "string",
                        "description": "user code",
                        "name": "code",
                        "in": "query",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "403": {
                        "description": "Forbidden",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "429": {
                        "description": "Too Many Requests",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "500": {
                        "description": "Internal Server Error",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        },
        "/github/callback": {
            "get": {
                "description": "GithubCallback logs in a user with Github",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "github",
                    "callback"
                ],
                "summary": "GithubCallback logs in a user with Github",
                "responses": {
                    "307": {
                        "description": "Temporary Redirect",
                        "headers": {
                            "Location": {
                                "type": "string",
                                "description": "Redirects to Next URL"
                            }
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "403": {
                        "description": "Forbidden",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "404": {
                        "description": "Not Found",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "500": {
                        "description": "Internal Server Error",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        },
        "/github/login": {
            "get": {
                "description": "GithubLogin logs in a user with Github",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "github",
                    "login"
                ],
                "summary": "GithubLogin logs in a user with Github",
                "parameters": [
                    {
                        "type": "string",
                        "description": "Next Redirect URL",
                        "name": "next",
                        "in": "query"
                    },
                    {
                        "type": "string",
                        "description": "Organization",
                        "name": "organization",
                        "in": "query"
                    },
                    {
                        "type": "string",
                        "description": "Device Flow Identifier",
                        "name": "identifier",
                        "in": "query"
                    }
                ],
                "responses": {
                    "307": {
                        "description": "Temporary Redirect",
                        "headers": {
                            "Location": {
                                "type": "string",
                                "description": "Redirects to Github"
                            }
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "500": {
                        "description": "Internal Server Error",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        },
        "/google/callback": {
            "get": {
                "description": "GoogleCallback logs in a user with Google",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "google",
                    "callback"
                ],
                "summary": "GoogleCallback logs in a user with Google",
                "responses": {
                    "307": {
                        "description": "Temporary Redirect",
                        "headers": {
                            "Location": {
                                "type": "string",
                                "description": "Redirects to Next URL"
                            }
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "403": {
                        "description": "Forbidden",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "404": {
                        "description": "Not Found",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "500": {
                        "description": "Internal Server Error",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        },
        "/google/login": {
            "get": {
                "description": "GoogleLogin logs in a user with Google",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "google",
                    "login"
                ],
                "summary": "GoogleLogin logs in a user with Google",
                "parameters": [
                    {
                        "type": "string",
                        "description": "Next Redirect URL",
                        "name": "next",
                        "in": "query"
                    },
                    {
                        "type": "string",
                        "description": "Organization",
                        "name": "organization",
                        "in": "query"
                    },
                    {
                        "type": "string",
                        "description": "Device Flow Identifier",
                        "name": "identifier",
                        "in": "query"
                    }
                ],
                "responses": {
                    "307": {
                        "description": "Temporary Redirect",
                        "headers": {
                            "Location": {
                                "type": "string",
                                "description": "Redirects to Google"
                            }
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "500": {
                        "description": "Internal Server Error",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        },
        "/health": {
            "get": {
                "description": "Health returns the status of the various services",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "health"
                ],
                "summary": "Health returns the status of the various services",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/models.HealthResponse"
                        }
                    },
                    "500": {
                        "description": "Internal Server Error",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        },
        "/logout": {
            "post": {
                "description": "Logout logs out a user",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "logout"
                ],
                "summary": "Logout logs out a user",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "500": {
                        "description": "Internal Server Error",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        },
        "/magic/callback": {
            "get": {
                "description": "MagicCallback validates the magic link and logs in the user",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "magic",
                    "callback"
                ],
                "summary": "MagicCallback validates the magic link and logs in the user",
                "parameters": [
                    {
                        "type": "string",
                        "description": "magic link token",
                        "name": "token",
                        "in": "query",
                        "required": true
                    }
                ],
                "responses": {
                    "307": {
                        "description": "Temporary Redirect",
                        "headers": {
                            "Location": {
                                "type": "string",
                                "description": "Redirects to Next URL"
                            }
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "403": {
                        "description": "Forbidden",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "404": {
                        "description": "Not Found",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "500": {
                        "description": "Internal Server Error",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        },
        "/magic/flow": {
            "post": {
                "description": "MagicFlow starts the magic link flow",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "device",
                    "login"
                ],
                "summary": "MagicFlow starts the magic link flow",
                "parameters": [
                    {
                        "type": "string",
                        "description": "email address",
                        "name": "email",
                        "in": "query",
                        "required": true
                    },
                    {
                        "type": "string",
                        "description": "Next Redirect URL",
                        "name": "next",
                        "in": "query"
                    },
                    {
                        "type": "string",
                        "description": "Organization",
                        "name": "organization",
                        "in": "query"
                    },
                    {
                        "type": "string",
                        "description": "Device Flow Identifier",
                        "name": "identifier",
                        "in": "query"
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "500": {
                        "description": "Internal Server Error",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        },
        "/servicekey/login": {
            "post": {
                "description": "ServiceKeyLogin logs in a user with their Service Key",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "servicekey",
                    "login"
                ],
                "summary": "ServiceKeyLogin logs in a user with their Service Key",
                "parameters": [
                    {
                        "type": "string",
                        "description": "Service Key",
                        "name": "servicekey",
                        "in": "query",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/models.ServiceKeyLoginResponse"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "500": {
                        "description": "Internal Server Error",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        },
        "/userinfo": {
            "post": {
                "description": "UserInfo checks if a user is logged in and returns their info",
                "consumes": [
                    "application/json"
                ],
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "login"
                ],
                "summary": "UserInfo checks if a user is logged in and returns their info",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/models.UserInfoResponse"
                        }
                    },
                    "400": {
                        "description": "Bad Request",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "401": {
                        "description": "Unauthorized",
                        "schema": {
                            "type": "string"
                        }
                    },
                    "500": {
                        "description": "Internal Server Error",
                        "schema": {
                            "type": "string"
                        }
                    }
                }
            }
        }
    },
    "definitions": {
        "auth.Kind": {
            "type": "string",
            "enum": [
                "session",
                "api",
                "service"
            ],
            "x-enum-varnames": [
                "KindSession",
                "KindAPIKey",
                "KindServiceSession"
            ]
        },
        "models.ConfigResponse": {
            "type": "object",
            "properties": {
                "default_next_url": {
                    "type": "string"
                },
                "device_enabled": {
                    "type": "boolean"
                },
                "endpoint": {
                    "type": "string"
                },
                "github_enabled": {
                    "type": "boolean"
                },
                "google_enabled": {
                    "type": "boolean"
                },
                "magic_enabled": {
                    "type": "boolean"
                }
            }
        },
        "models.DeviceCallbackResponse": {
            "type": "object",
            "properties": {
                "identifier": {
                    "type": "string"
                }
            }
        },
        "models.DeviceFlowResponse": {
            "type": "object",
            "properties": {
                "device_code": {
                    "type": "string"
                },
                "polling_rate": {
                    "type": "integer"
                },
                "user_code": {
                    "type": "string"
                }
            }
        },
        "models.HealthResponse": {
            "type": "object",
            "properties": {
                "subscriptions": {
                    "type": "boolean"
                }
            }
        },
        "models.ServiceKeyLoginResponse": {
            "type": "object",
            "properties": {
                "organization": {
                    "type": "string"
                },
                "resources": {
                    "type": "array",
                    "items": {
                        "$ref": "#/definitions/servicekey.Resource"
                    }
                },
                "service_key_id": {
                    "type": "string"
                },
                "service_session_id": {
                    "type": "string"
                },
                "service_session_secret": {
                    "type": "string"
                },
                "user_id": {
                    "type": "string"
                }
            }
        },
        "models.UserInfoResponse": {
            "type": "object",
            "properties": {
                "email": {
                    "type": "string"
                },
                "organization": {
                    "type": "string"
                },
                "session": {
                    "enum": [
                        "session",
                        "api",
                        "service"
                    ],
                    "allOf": [
                        {
                            "$ref": "#/definitions/auth.Kind"
                        }
                    ]
                }
            }
        },
        "servicekey.Resource": {
            "type": "object",
            "properties": {
                "id": {
                    "description": "ID is the resource's unique identifier",
                    "type": "string"
                },
                "type": {
                    "description": "Type is the resource's type",
                    "type": "string"
                }
            }
        }
    }
}`

// SwaggerInfoauthAPI holds exported Swagger Info so clients can modify it
var SwaggerInfoauthAPI = &swag.Spec{
	Version:          "1.0",
	Host:             "localhost:8080",
	BasePath:         "/v1",
	Schemes:          []string{"https"},
	Title:            "Auth API V1",
	Description:      "Auth API, V1",
	InfoInstanceName: "authAPI",
	SwaggerTemplate:  docTemplateauthAPI,
}

func init() {
	swag.Register(SwaggerInfoauthAPI.InstanceName(), SwaggerInfoauthAPI)
}
