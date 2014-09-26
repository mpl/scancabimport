package datastore

import (
	"bytes"
	"errors"
	"io/ioutil"
	"net/http"

	"github.com/mpl/scancabimport/third_party/code.google.com/p/goprotobuf/proto"
)

type client struct {
	transport http.RoundTripper
}

func (c *client) call(url string, req proto.Message, resp proto.Message) (err error) {
	println("CLIENT CALL")
	client := http.Client{Transport: c.transport}
	payload, err := proto.Marshal(req)
	if err != nil {
		return
	}
	r, err := client.Post(url, "application/x-protobuf", bytes.NewBuffer(payload))
	if err != nil {
		return
	}
	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if r.StatusCode != http.StatusOK {
		if err != nil {
			return err
		}
		return errors.New("datastore: error during call: " + string(body))
	}
	if err != nil {
		return err
	}
	if err = proto.Unmarshal(body, resp); err != nil {
		return
	}
//	if err := ioutil.WriteFile("/home/mpl/datastore.xml", []byte(resp.String()), 0700); err != nil {
//		return err
//	}
	return
}
