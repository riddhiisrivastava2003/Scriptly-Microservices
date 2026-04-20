package com.scriptly.auth_service.repository;

import com.scriptly.auth_service.entity.User;
import com.scriptly.auth_service.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);
    Optional<User> findByUsername(String username);
    boolean existsByEmail(String email);
    boolean existsByUsername(String username);
    List<User> findAllByRole(Role role);
    long countByRole(Role role);
    List<User> findAllByOrderByCreatedAtDesc();

    @Query("""
            select u from User u
            where lower(u.username) like lower(concat('%', :keyword, '%'))
               or lower(u.email) like lower(concat('%', :keyword, '%'))
               or lower(coalesce(u.fullName, '')) like lower(concat('%', :keyword, '%'))
            order by u.createdAt desc
            """)
    List<User> searchByKeyword(@Param("keyword") String keyword);
}
