class ArticlesController < ApplicationController
  before_action :authorize, only: [:edit, :update]
  before_action :set_article, only: [:show, :edit, :update, :destroy]

  def index
    @articles = Article.all
  end

  def new
    @article = Article.new
  end

  def edit
  end

  def create
    @article = Article.new(article_params)

    if @article.save
      redirect_to articles_url, notice: 'Article created'
    else
      render :new
    end
  end

  def update
    if @article.update(article_params)
      redirect_to @article, notice: 'Article updated'
    else
      render :edit
    end
  end

  def destroy
    @article.destroy
    redirect_to articles_path, notice: 'Article removed'
  end

  private

  def article_params
    params.require(:article).permit(:title, :body)
  end

  def set_article
    @article = Article.find(params[:id])
  end
end
