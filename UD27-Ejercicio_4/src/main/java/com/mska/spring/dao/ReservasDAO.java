package com.mska.spring.dao;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.mska.spring.dto.Reservas;

@Repository
public interface ReservasDAO extends JpaRepository<Reservas, Long>{

	/**
	 * Se heredan los métodos CRUD básicos de la clase JpaRepository se utiliza un
	 * String como parámetro para la entidad Reservas.
	 */
}
