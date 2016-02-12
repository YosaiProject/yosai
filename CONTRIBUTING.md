# How to Contribute to the Yosai Project

There are many ways you can contribute to the Yosai Project, from bug identification
to refactoring, writing extensions or creating integrations.  It is important 
that our working environment be friendly and welcoming to all potential contributors.  
With that given, you are to abide by some simple guidelines outlined in the 
[Code of Conduct](https://yosaiproject.github.io/code_of_conduct).

## Easy Ways to Contribute

The Yosai community has a Google Group.  The [Community page](https://yosaiproject.github.io/community) i
has more information about that.

If you want to file a bug report, suggest a feature, or ask a code-related
question, please go to the `yosaiproject/yosai` repository on GitHub and
[create a new Issue](https://github.com/yosaiproject/yosai/issues/new). (You
will need a [GitHub account](https://github.com/signup/free) (free).) Please
describe the issue clearly, including steps to reproduce when you report a bug.


## How to Contribute Code or Documentation

### Step 0 - Prepare and Familiarize Yourself

To contribute code or documentation, you need a [GitHub account](https://github.com/signup/free).

Familiarize yourself with Yosai's coding convention, architecture, and documentation 
 including:

* testing requirements
* documentation strategy
* [semantic versioning](http://semver.org/)

### Step 1 - Fork yosai on GitHub

In your web browser, go to [the Yosai repository on GitHub](https://github.com/yosaiproject/yosai) 
and click the `Fork` button in the top right corner. This creates a new Git 
repository named `yosai` in _your_ GitHub account.

### Step 2 - Clone Your Fork

(This only has to be done once.) In your local terminal, use Git to clone *your* 
`yosai` repository to your local computer. Also add the original GitHub 
yosaiproject/yosai repository as a remote named `upstream` (a convention):

```bash
git clone git@github.com:your-github-username/yosai.git
cd yosai
git add upstream git@github.com:yosaiproject/yosai.git
```

### Step 3 - Fetch and Merge the Latest from `upstream/develop`

Switch to the `develop` branch locally, fetch all `upstream` branches, and
merge the just-fetched `upstream/develop` branch with the local `develop`
branch: 
```bash
git checkout develop
git fetch upstream
git merge upstream/develop
```

### Step 4 - Create a New Branch for Each Bug/Feature

If your new branch is to **fix a bug** identified in a specific GitHub Issue 
with number `ISSNO`, then name your new branch `bug/ISSNO/short-description-here`. 
For example, `bug/12/fix-password-salt-format`.

If your new branch is to **add a feature** requested in a specific GitHub Issue
with number `ISSNO`, then name your new branch `feat/ISSNO/short-description-here`. 
For example, `feat/237/multi-factor-authentication`.

Otherwise, please give your new branch a short, descriptive, all-lowercase name.
```bash
git checkout -b new-branch-name
```

### Step 5 - Make Edits, git add, git commit

With your new branch checked out locally, make changes or additions to the code
or documentation, git add them, and git commit them.  
```bash
git add new-or-changed-file
git commit -m "Short description of new or changed things"
```

Remember to write tests for new code, including unit (isolated) tests and 
integrated tests.  Target a unit test coverage ratio of 90% tested.  Test
coverage of less than 90% affected source code will be scrutinized and potentially 
rejected.

Please run all existing tests to make sure you didn't break something.  Tox
is provided to help you run tests.

Remember to write or modify documentation to reflect your additions or changes.

You will want to merge changes from upstream (i.e. the original repository)
into your new branch from time to time, using something like: 
```bash
git fetch upstream
git merge upstream/develop
```

### Step 6 - Push Your New Branch to origin

Ensure that you've **commited** all that you want to include in your pull request. 
Then push your new branch to origin (i.e. _your_ remote yosai repository).

```bash
git push origin new-branch-name
```

### Step 7 - Create a Pull Request 

Go to the GitHub website and to _your_ remote yosai repository (i.e. something 
like https://github.com/your-user-name/yosai). 

See [GitHub's documentation on how to initiate and send a pull request]
(https://help.github.com/articles/using-pull-requests/). Note that the
destination repository should be `yosaiproject/yosai` and the destination
branch will typically be `develop`.

Send the pull request.

Someone will then merge your branch or suggest changes. If we suggest changes,
you won't have to open a new pull request, you can just push new code to the
same branch (on `origin`) as you did before creating the pull request.

## Quick Links

* [General GitHub Documentation](https://help.github.com/)
* [Code of Conduct](./code_of_conduct.md)
