package pcmarket.pcmarket.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;
import pcmarket.pcmarket.entity.Blog;
@RepositoryRestResource(path = "blog")
public interface BlogRepository extends JpaRepository<Blog,Integer> {
}
