package pcmarket.pcmarket.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;
import pcmarket.pcmarket.entity.Comments;
@RepositoryRestResource(path = "comments")
public interface CommentsRepository extends JpaRepository<Comments,Integer> {
}
