---
layout: default
title: Home
---

<div class="container-list">
  <!-- <div class="post-list"> -->

    {% for post in site.posts limit:5%}

    <div class="card">
      <div class="card-block">
        <h4 class="card-title"><a href="{{ post.url | prepend: site.baseurl }}">{{ post.title}}</a></h4>
        <time class="card-subtitle mb-2 text-muted">{{ post.date | date: "%d %B %Y, %A" }}</time>
      <div class="card-text">
        <p>
          {% if post.description %}
          {{ post.description}}
          {% else %}
          {{ post.excerpt }}
          {% endif %} 
          <a class="read-more" href="{{ post.url | prepend: site.baseurl }}"> »  </a>
        </p> 
      </div>
      <footer class="post_meta">


        {% if post.location %}
        <span class="author-location">
          <div data-icon="ei-location"></div>
          <a href=https://www.google.com/maps/place/{{post.location}}">{{ post.location }}</a>
        </span>
        {% endif %}
        <!--
        {% for category in post.categories %}
        <a href="{{"/category/" | append: category | prepend: site.baseurl }}">
          <data data-icon="ei-archive"></data>
          {{category}}</a>
        {% endfor %}
        -->

        <!--
        {% if post.author %}
        <span class="author_meta">
          <img src="{{site.baseurl}}/assets/img/{{post.author}}.jpg"></img>
          <span>David Lin</span>
        </span>
        {% endif %}
        -->

        <!--p class="readmore">
          <a href=""><data data-icon="ei-arrow-right"></data>Read this article  </a>
        </p-->
      </footer>
      <hr/>
      </div>
    </div>
    {% endfor %}

    
  <!-- </div> -->
</div>
