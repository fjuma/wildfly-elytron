# Elytron Project Website Based on Jekyll

## Getting Started

These instructions will allow you to run the Elytron website locally for development and testing purposes.

### Installation
[Jekyll static site generator docs](https://jekyllrb.com/docs/).

1. Install a full [Ruby development environment](https://jekyllrb.com/docs/installation/)
2. Install [bundler](https://jekyllrb.com/docs/ruby-101/#bundler)  [gems](https://jekyllrb.com/docs/ruby-101/#gems) 
  
        gem install bundler

3. Fork the [project repository](https://github.com/wildfly-security/wildfly-elytron), then clone your fork.
  
        git clone git@github.com:YOUR_USER_NAME/wildfly-elytron.git

4. Change into the project directory:
  
        cd wildfly-elytron

5. Checkout the [gh-pages](https://github.com/wildfly-security/wildfly-elytron/tree/gh-pages) branch:
  
        git checkout gh-pages

6. Use bundler to fetch all required gems in their respective versions

        bundle install

7. Build the site and make it available on a local server
  
        bundle exec jekyll serve
        
8. Now browse to http://localhost:4000

> If you encounter any unexpected errors during the above, please refer to the [troubleshooting](https://jekyllrb.com/docs/troubleshooting/#configuration-problems) page or the [requirements](https://jekyllrb.com/docs/installation/#requirements) page, as you might be missing development headers or other prerequisites.


**For more regarding the use of Jekyll, please refer to the [Jekyll Step by Step Tutorial](https://jekyllrb.com/docs/step-by-step/01-setup/).**

## Writing a blog

To write a blog post:

- Add an author entry in [_data/authors.yaml](https://github.com/wildfly-security/wildfly-elytron/tree/gh-pages/_data/authors.yaml)
    - `emailhash` is used to fetch your picture from the Gravatar service
- Create a blog post entry under [_posts](https://github.com/wildfly-security/wildfly-elytron/tree/gh-pages/_posts)
    - The file name should be `yyyy-mm-dd-slug.adoc`
- Your blog post should be in asciidoc format (take a look at other blogs posts in the _posts directoy to see examples)
    - To view your blog post locally, browse to http://localhost:4000/blog and then click on your post
- Submit a pull request against the gh-pages branch

