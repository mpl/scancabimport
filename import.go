/*
Copyright 2014 The Camlistore Authors

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

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"camlistore.org/pkg/client"
	"camlistore.org/pkg/schema"

	"github.com/mpl/scancabimport/third_party/github.com/golang/oauth2"
	"github.com/mpl/scancabimport/third_party/google.golang.org/cloud/datastore"
)

var (
	verbose = flag.Bool("v", false, "verbose")
	skipGAE = flag.Bool("skipgae", false, "do not refetch from GAE, reuse metadata stored in .json in previous run")
)

const (
	projectId = "scancabcamli"

	tokenCacheFile = "tokencache.json"
	scansDir       = "scans"             // where the scanned files will be stored
	mediaObjects   = "mediaObjects.json" // scans metadata
	documents      = "documents.json"    // documents metadata
)

var (
	ds *datastore.Dataset
	cl *http.Client
)

// UserInfo represents the metadata associated with the Google User
// currently logged-in to the app
type UserInfo struct {
	// User stores the email address of the currently logged-in user
	// this is used as the primary key
	User string

	// MediaObjects is a count of the MediaObjects currently associated with this user
	MediaObjects int64

	// UploadPassword is a plain-text string that protects the scan upload API
	UploadPassword string
}

// MediaObject represents the metadata associated with each individual uploaded scan
type MediaObject struct {
	// Owner is the key of the UserInfo of the user that uploaded the file
	Owner *datastore.Key `json:"-"`

	// Id is the entity ID of the key associated with this MediaObject struct
	Id int64 `datastore:"-"`

	// Blob is the key of blobstore entry with this uploaded file
	Blob string `json:"-"`

	// Creation the time when this struct was originally created
	Creation time.Time

	// ContentType is the MIME-type of the uploaded file.
	// As the mime/multipart package does not detect Content-Type
	// before sending the file in the command line client, this is
	// detected in the webapp and so this field may differ from the
	// content-type for the associated blob in the blobstore
	ContentType string

	// Filename is the name of the file when it was uploaded
	Filename string

	// Size in bytes of the uploaded file
	Size int64

	// Document is the key of the associated Document struct.
	// A Document has many MediaObjects. When newly uploaded,
	// a MediaObject is not associated with a Document.
	Document *datastore.Key

	// LacksDocument is false when this MediaObject is associated with a Document.
	// When newly uploaded, a MediaObject is not associated with a Document.
	LacksDocument bool
}

// Document is a structure that groups scans into a logical unit.
// A letter (Stored as a document) could have several pages
// (each is a MediaObject), for example.
type Document struct {
	// Owner is the key of the UserInfo of the user that created the Document
	Owner *datastore.Key

	// Pages are the keys of each Media Object that contitute this Document
	Pages []*datastore.Key

	// Id is the entity ID of the key associated with this Document struct
	Id int64 `datastore:"-"`

	// DocDate is the user-nominated date associated with this document. It can
	// store any date the user likes but is intended to be when the document was
	// received, or, perhaps, written or sent
	DocDate time.Time

	// NoDate is false when DocDate has been set by the user
	NoDate bool

	// Creation is the date the Document struct was created
	Creation time.Time

	// Title is the user-nominated title of the document
	Title string

	// Description is the user-nominated description of the document
	Description string

	// Tags is the slice of zero or more tags associated with the document by the user
	Tags []string

	// LowercaseTags is the content of Tags but stored lowercase as a
	// canonical version so searches on tags can be case-insensitive
	LowercaseTags string

	// NoTags is true when Tags is empty
	NoTags bool

	// PhysicalLocation is the user-nominated description of the location
	// of the physical document of which the MediaObjects associated with this
	// Document are scans
	PhysicalLocation string

	// DueDate is the user-nominated date that the document is "due". The
	// meaning of what "due" means in relation to each particular document
	// is up to the user
	DueDate time.Time
}

const (
	// TODO(mpl): figure out how high these can be cranked up.
	scansRequestLimit = 5
	docsRequestLimit  = 5
)

func getScans() ([]*MediaObject, error) {
	var scans []*MediaObject
	query := ds.NewQuery("MediaObject")
	query = query.Limit(scansRequestLimit)
	for {
		sc := make([]*MediaObject, scansRequestLimit)
		keys, next, err := ds.RunQuery(query, sc)
		if err != nil {
			return nil, err
		}
		// get the key id and store it in the media object because we'll need it
		// to fetch the corresponding file from the blobstore later.
		for i, obj := range sc {
			if obj == nil {
				break
			}
			obj.Id = keys[i].ID()
		}
		scans = append(scans, sc...)
		if next == nil {
			break
		}
		query = next
	}
	return scans, nil
}

/*
func getDocuments() ([]*Document, error) {
	var docs []*Document
	query := ds.NewQuery("Document")
	query = query.Limit(scansRequestLimit)
	for {
		dc := make([]*Document, docsRequestLimit)
		//		keys, next, err := ds.RunQuery(query, dc)
		_, next, err := ds.RunQuery(query, dc)
		if err != nil {
			return nil, err
		}
		docs = append(docs, dc...)
		if next == nil {
			break
		}
		query = next
	}
	return docs, nil
}
*/

func getScannedFile(resourceId, filename string) error {
	if resourceId == "" {
		log.Printf("WARNING: Not fetching scan because empty resourceId")
		return nil
	}
	if resourceId == "" {
		log.Printf("WARNING: Not fetching scan because empty filename")
		return nil
	}
	filePath := filepath.Join(scansDir, filename)
	if _, err := os.Stat(filePath); err == nil {
		log.Printf("%s already exists, skipping download.", filePath)
		return nil
	}
	resp, err := cl.Get("https://" + projectId + ".appspot.com/resource/" + resourceId + "/" + filename)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("Status %v", resp.Status)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filePath, body, 0700)
}

func cacheToken(tok *oauth2.Token) error {
	file, err := os.OpenFile(tokenCacheFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if err := file.Close(); err != nil {
			panic(err)
		}
	}()
	if err := json.NewEncoder(file).Encode(tok); err != nil {
		return err
	}
	return nil
}

func cachedToken() (*oauth2.Token, error) {
	file, err := os.Open(tokenCacheFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	tok := &oauth2.Token{}
	if err := json.NewDecoder(file).Decode(tok); err != nil {
		return nil, err
	}
	return tok, nil
}

func transportFromAPIKey() (*oauth2.Transport, error) {
	// APIkey credentials. used to auth against both the app itself, and the datastore API.
	clientId := os.Getenv("CLIENTID")
	if clientId == "" {
		return nil, fmt.Errorf("CLIENTID not set")
	}
	clientSecret := os.Getenv("CLIENTSECRET")
	if clientSecret == "" {
		return nil, fmt.Errorf("CLIENTSECRET not set")
	}
	conf, err := oauth2.NewConfig(&oauth2.Options{
		Scopes: []string{"https://www.googleapis.com/auth/appengine.admin", // TODO(mpl): maybe not needed?
			"https://www.googleapis.com/auth/datastore",
			"https://www.googleapis.com/auth/userinfo.email"},
		ClientID:     clientId,
		ClientSecret: clientSecret,
		RedirectURL:  "urn:ietf:wg:oauth:2.0:oob",
	},
		"https://accounts.google.com/o/oauth2/auth",
		"https://accounts.google.com/o/oauth2/token")
	if err != nil {
		return nil, err
	}

	token, err := cachedToken()
	if err == nil {
		tr := conf.NewTransport()
		tr.SetToken(token)
		return tr, nil
	}

	// Redirect user to consent page to ask for permission
	// for the scopes specified above.
	url := conf.AuthCodeURL("state", "online", "auto")
	// url := conf.AuthCodeURL("state", "offline", "auto")
	fmt.Printf("Visit the URL for the auth dialog:\n%v\n", url)
	fmt.Println("And enter the authorization string displayed in your browser:")

	input := bufio.NewReader(os.Stdin)
	line, _, err := input.ReadLine()
	if err != nil {
		log.Fatalf("Failed to read line: %v", err)
	}
	authorizationCode := strings.TrimSpace(string(line))
	tr, err := conf.NewTransportWithCode(authorizationCode)
	if err != nil {
		return nil, err
	}
	if err := cacheToken(tr.Token()); err != nil {
		return nil, err
	}
	return tr, nil
}

func writeObjects(scans []*MediaObject, docs map[int64]*Document) error {
	f, err := os.OpenFile(mediaObjects, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(f).Encode(scans); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	docsArray := make([]*Document, len(docs))
	for _, v := range docs {
		docsArray = append(docsArray, v)
	}
	f, err = os.OpenFile(documents, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(f).Encode(docsArray); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return nil
}

func getUsers(scans []*MediaObject) (map[int64]*UserInfo, error) {
	users := make(map[int64]*UserInfo)
	for _, v := range scans {
		if v == nil {
			continue
		}
		if *verbose {
			fmt.Printf("%v\n", v)
		}
		if v.Owner != nil {
			userId := v.Owner.ID()
			if _, ok := users[userId]; !ok {
				userInfo := &UserInfo{}
				if err := ds.Get(v.Owner, userInfo); err != nil {
					return nil, err
				}
				users[userId] = userInfo
				if *verbose {
					fmt.Printf("Owner: %v\n", userInfo)
				}
			}
		}
	}
	return users, nil
}

func getDocuments(scans []*MediaObject) (map[int64]*Document, error) {
	docs := make(map[int64]*Document)
	for _, v := range scans {
		if v == nil {
			continue
		}
		if v != nil && !v.LacksDocument && v.Document != nil {
			docId := v.Document.ID()
			if _, ok := docs[docId]; ok {
				if *verbose {
					fmt.Printf("Document cache hit: %d\n", docId)
				}
				continue
			}
			document := &Document{}
			if err := ds.Get(v.Document, document); err != nil {
				return nil, err
			}
			document.Id = docId
			docs[docId] = document
			if *verbose {
				fmt.Printf("Document: %v\n", document)
			}
		}
	}
	return docs, nil
}

func main() {
	flag.Parse()

	if err := os.MkdirAll(scansDir, 0700); err != nil {
		log.Fatal(err)
	}

	tr, err := transportFromAPIKey()
	if err != nil {
		log.Fatal(err)
	}
	cl = &http.Client{Transport: tr}

	ds, err = datastore.NewDatasetWithTransport(projectId, tr)
	if err != nil {
		log.Fatal(err)
	}

	if !*skipGAE {
		scans, err := getScans()
		if err != nil {
			log.Fatal(err)
		}

		users, err := getUsers(scans)
		if err != nil {
			log.Fatal(err)
		}
		_ = users
		for _, v := range scans {
			if v == nil {
				continue
			}
			if err := getScannedFile(fmt.Sprintf("%d", v.Id), v.Filename); err != nil {
				log.Fatal(err)
			}
		}
		docs, err := getDocuments(scans)
		if err != nil {
			log.Fatal(err)
		}

		if err := writeObjects(scans, docs); err != nil {
			log.Fatal(err)
		}
	}

	scansBytes, err := ioutil.ReadFile(mediaObjects)
	if err != nil {
		log.Fatal(err)
	}
	docsBytes, err := ioutil.ReadFile(documents)
	if err != nil {
		log.Fatal(err)
	}
	var scans []*MediaObject
	if err := json.Unmarshal(scansBytes, &scans); err != nil {
		log.Fatalf("decoding scans: %v", err)
	}
	var docs []*Document
	if err := json.Unmarshal(docsBytes, &docs); err != nil {
		log.Fatalf("decoding documents: %v", err)
	}

	for _, v := range scans {
		fmt.Printf("%v\n", v)
	}
	for _, v := range docs {
		fmt.Printf("%v\n", v)
	}
	return

	if err := uploadObjects(scansToMap(scans), docs); err != nil {
		log.Fatal(err)
	}
}

type scanAttrs map[string]string

func scansToMap(mo []*MediaObject) map[int64]scanAttrs {
	m := make(map[int64]scanAttrs, len(mo))
	for _, v := range mo {
		m[v.Id] = v.attrs()
	}
	return m
}

func (mo *MediaObject) attrs() scanAttrs {
	attrs := make(map[string]string)
	ctime := mo.Creation.Format(time.RFC3339) // TODO(mpl): make sure of format
	attrs["creationTime"] = ctime
	attrs["contentType"] = mo.ContentType
	attrs["filename"] = mo.Filename
	attrs["size"] = fmt.Sprintf("%d", mo.Size)
	attrs["LacksDocument"] = fmt.Sprintf("%v", mo.LacksDocument)
	// TODO(mpl): Pages into PageList or something
	return attrs
}

func toSlice(m map[string]string) []string {
	var s []string
	for k, v := range m {
		s = append(s, k, v)
	}
	return s
}

func (mo *Document) attrs() map[string]string {
	attrs := make(map[string]string)
	modTime := mo.DocDate.Format(time.RFC3339) // TODO(mpl): make sure of format
	ctime := mo.Creation.Format(time.RFC3339)  // TODO(mpl): make sure of format
	dueDate := mo.DueDate.Format(time.RFC3339) // TODO(mpl): make sure of format
	attrs["creationTime"] = ctime
	attrs["modTime"] = modTime
	attrs["noDate"] = fmt.Sprintf("%v", mo.NoDate)
	attrs["title"] = mo.Title
	//        attrs["tags"] = mo.Tags // TODO(mpl): do it properly
	attrs["noTags"] = fmt.Sprintf("%v", mo.NoTags)
	attrs["physicalLocation"] = mo.PhysicalLocation
	attrs["dueDate"] = dueDate
	return attrs
}

// TODO(mpl): owner?

func uploadObjects(scans map[int64]scanAttrs, docs []*Document) error {
	camcl := client.NewOrFail()
	// first pass: upload scans and their attrs
	for scanId, scanAttrs := range scans {
		pr, err := camcl.UploadNewPermanode()
		if err != nil {
			return fmt.Errorf("could not create permanode for scan %v: %v", scanId, err)
		}

		for attr, val := range scanAttrs {
			if _, err := camcl.UploadAndSignBlob(schema.NewSetAttributeClaim(pr.BlobRef, attr, val)); err != nil {
				return fmt.Errorf("could not set (%v, %v) for scan permanode %v: %v", attr, val, pr, err)
			}
		}

		// TODO(mpl): upload actual scan file!

		// keeping track of the permanode, so we have it handy when doing the relation with the doc
		scanAttrs["permanode"] = pr.BlobRef.String()
		scans[scanId] = scanAttrs
	}

	// second pass: upload docs
	for _, doc := range docs {
		pr, err := camcl.UploadNewPermanode()
		if err != nil {
			return fmt.Errorf("could not create permanode for doc %v: %v", doc.Id, err)
		}

		for attr, val := range doc.attrs() {
			if _, err := camcl.UploadAndSignBlob(schema.NewSetAttributeClaim(pr.BlobRef, attr, val)); err != nil {
				return fmt.Errorf("could not set (%v, %v) for document permanode %v: %v", attr, val, pr, err)
			}
		}

		// third pass: pages of each document
		pageNb := 1
		for _, pageKey := range doc.Pages {
			pageId := pageKey.ID()
			pn, ok := scans[pageId]["permanode"]
			if !ok {
				return fmt.Errorf("could not find permanode for scan %v", pageId)
			}
			camliPath := fmt.Sprintf("camliPath:%d", pageNb)
			if _, err := camcl.UploadAndSignBlob(
				schema.NewSetAttributeClaim(pr.BlobRef, camliPath, pn)); err != nil {
				return fmt.Errorf("could not set (%v, %v) for document permanode %v: %v", camliPath, pn, pr, err)
			}
		}
	}
	return nil

}
