package client

import (
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
)

var upgrader = websocket.Upgrader{}

func echo(w http.ResponseWriter, r *http.Request) {
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer c.Close()
	for {
		mt, message, err := c.ReadMessage()
		if err != nil {
			break
		}
		err = c.WriteMessage(mt, message)
		if err != nil {
			break
		}
	}
}

func TestQuorumClient(t *testing.T) {
	// Create test rpc websocket server with the echo handler.
	rpcServer := httptest.NewServer(http.HandlerFunc(echo))
	defer rpcServer.Close()
	// Convert http://127.0.0.1 to ws://127.0.0.1.
	rpcurl := "ws" + strings.TrimPrefix(rpcServer.URL, "http")

	// Connect to the server.
	ws, _, err := websocket.DefaultDialer.Dial(rpcurl, nil)
	assert.NoError(t, err)
	_ = ws.Close()

	_, err = NewQuorumClient("ws://invalid")
	assert.Error(t, err)

	_, err = NewQuorumClient(rpcurl)
	assert.NoError(t, err)
}

func TestQuorumGraphQLClient(t *testing.T) {
	// Create test rpc websocket server with the echo handler.
	rpcServer := httptest.NewServer(http.HandlerFunc(echo))
	defer rpcServer.Close()
	// Convert http://127.0.0.1 to ws://127.0.0.1.
	rpcurl := "ws" + strings.TrimPrefix(rpcServer.URL, "http")

	// Create test graphql server.
	graphqlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := ioutil.ReadAll(r.Body)
		if strings.Contains(string(b), "block") {
			io.WriteString(w, `{
				"data": {
					"block": {
						"number": "0x6"
					}
				}
			}`)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer graphqlServer.Close()

	// Connect to the server.
	ws, _, err := websocket.DefaultDialer.Dial(rpcurl, nil)
	assert.NoError(t, err)
	_ = ws.Close()

	_, err = NewQuorumGraphQLClient("ws://invalid", "http://invalid")
	assert.Error(t, err)

	_, err = NewQuorumGraphQLClient(rpcurl, "http://invalid")
	assert.Error(t, err)

	_, err = NewQuorumGraphQLClient(rpcurl, graphqlServer.URL)
	assert.NoError(t, err)
}

func TestStubQuorumClient(t *testing.T) {
	mockGraphQL := map[string]map[string]interface{}{
		"query": {"hello": "world"},
	}
	mockRPC := map[string]interface{}{
		"rpc_method": "hi",
	}
	var err error
	c := NewStubQuorumClient(mockGraphQL, mockRPC)

	// test mock GraphQL
	var resp map[string]interface{}
	err = c.ExecuteGraphQLQuery(&resp, "query")
	assert.NoError(t, err)
	assert.Equal(t, "world", resp["hello"], "expected resp hello world, but got %v", resp["hello"])

	err = c.ExecuteGraphQLQuery(&resp, "random")
	assert.EqualError(t, err, "not found", "unexpected error message")

	// test mock RPC
	var res string
	err = c.RPCCall(&res, "rpc_method")
	assert.NoError(t, err)
	assert.Equal(t, "hi", res, "expected res hi, but got %v", res)

	err = c.RPCCall(&res, "rpc_nil")
	assert.EqualError(t, err, "not found", "unexpected error message")
}
