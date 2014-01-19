var fs = require('fs');

var Client = require('github2');

var repoPath = process.env['TRAVIS_REPO_SLUG'].split('/');
var commitSHA = process.env["TRAVIS_COMMIT"];

var user = repoPath[0];
var repo = repoPath[1];
var token = process.env['GITHUB_TOKEN'];

var pkg = JSON.parse(fs.readFileSync('package.json', { encoding: 'utf8' }));

var release = {
  "user": user,
  "repo": repo,
  "tag_name": "LatestDev",
  "name": "v" + pkg.version + " (Unstable)",
  "body": "The latest tested version of the master branch.\n\nTravis-CI build #" + process.env['TRAVIS_BUILD_NUMBER'] + ".",
  "prerelease": true
};

var client = new Client(
  {
    version: "3.0.0"
  }
);

client.authenticate(
  {
    "type": "oauth",
    "token": token
  }
);

client.gitdata.updateReference(
  {
    "user": release.user,
    "repo": release.repo,
    "ref": "tags/" + release.tag_name,
    "sha": commitSHA
  },
  function (err, res) {
    if (err) {
      client.gitdata.createReference(
        {
          "user": release.user,
          "repo": release.repo,
          "ref": "refs/tags/" + release.tag_name,
          "sha": commitSHA
        },
        function (err, res) {
          if (!err) {
            createRelease();
          } else {
            console.log("repos.createReference:\n", err);
          }
        }
      );
    } else {
      createRelease();
    }
  }
);

function createRelease() {
  client.repos.getAllReleases(
    {
      "user": release.user,
      "repo": release.repo
    },
    function (err, res) {
      if (!err) {
        var processed = false;
        res.forEach(function (item) {
          if (item.tag_name == "LatestDev") {
            if (!processed) {
              processed = true;
              release.id = item.id;
              client.repos.editRelease(
                release,
                function (err, res) {
                  if (!err) {
                    var assetCount = item.assets.length;
                    if (assetCount > 0) {
                      item.assets.forEach(function (asset) {
                        client.repos.deleteReleaseAsset(
                          {
                            "user": release.user,
                            "repo": release.repo,
                            "id": asset.id
                          },
                          function (err, res) {
                            if (--assetCount <= 0) {
                              uploadAssets();
                            }
                          }
                        );
                      });
                    } else {
                      uploadAssets();
                    }
                  } else {
                    console.log("repos.editRelease:\n", err);
                  }
                }
              );
            } else {
              client.repos.deleteRelease(
                {
                  "user": release.user,
                  "repo": release.repo,
                  "id": item.id
                },
                function (err, res) {
                  if (err) {
                    console.log("repos.deleteRelease:\n", err);
                  }
                }
              );
            }
          }
        });
        if (!processed) {
          client.repos.createRelease(
            release,
            function (err, res) {
              if (!err) {
                release.id = res.id;
                uploadAssets();
              } else {
                console.log("repos.createRelease:\n", err);
              }
            }
          );
        }
      } else {
        console.log("repos.getAllReleases:\n", err);
      }
    }
  );
}

function uploadAssets() {
  [
    [ "openpgp.min.js", "text/javascript" ],
    [ pkg.name + "-" + pkg.version + ".tgz", "application/x-tar"],
    [ "docs.zip", "application/zip" ]
  ].forEach(function (asset) {
    client.repos.uploadReleaseAsset(
      {
        "user": release.user,
        "repo": release.repo,
        "id": release.id,
        "name": asset[0],
        "content": fs.readFileSync("dist/" + asset[0]),
        "content_type": asset[1]
      },
      function (err, res) {
        if (err) {
          console.log("repos.uploadReleaseAsset:\n", err);
        }
      }
    );
  });
}
