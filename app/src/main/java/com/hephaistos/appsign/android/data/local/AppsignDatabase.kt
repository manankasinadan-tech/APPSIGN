package com.hephaistos.appsign.android.data.local

import android.content.Context
import androidx.room.Dao
import androidx.room.Database
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.sqlite.db.SupportSQLiteDatabase
import kotlinx.coroutines.flow.Flow

@Entity(tableName = "operation_history")
data class OperationHistoryEntity(
  @PrimaryKey(autoGenerate = true) val id: Long = 0,
  val timestampMs: Long = System.currentTimeMillis(),
  val operationType: String, // "VERIFY", "RESIGN", "KEY"
  val fileNames: String,
  val keyAlias: String? = null,
  val status: String, // "SUCCESS", "WARNING", "FAILED"
  val detailsSummary: String,
  val reportJson: String = "",
)

@Entity(tableName = "managed_keys")
data class ManagedKeyEntity(
  @PrimaryKey val keyId: String,
  val alias: String,
  val filePath: String,
  val mode: String, // "ASK_OPEN" or "ASK_LOCKED"
  val algorithm: String,
  val keySizeBits: Int,
  val sha256Fingerprint: String,
  val subjectDn: String,
  val createdAtIso: String,
)

@Dao
interface OperationHistoryDao {
  @Query(
    """
    SELECT id, timestampMs, operationType,
      SUBSTR(fileNames, 1, 512) AS fileNames,
      keyAlias, status,
      SUBSTR(detailsSummary, 1, 1024) AS detailsSummary,
      CASE WHEN LENGTH(reportJson) > 16384 THEN '' ELSE reportJson END AS reportJson
    FROM operation_history
    ORDER BY timestampMs DESC
    LIMIT 200
    """
  )
  fun observeAll(): Flow<List<OperationHistoryEntity>>

  @Insert(onConflict = OnConflictStrategy.REPLACE)
  suspend fun insert(entry: OperationHistoryEntity): Long

  @Query("DELETE FROM operation_history WHERE id = :id")
  suspend fun deleteById(id: Long)

  @Query("DELETE FROM operation_history")
  suspend fun clearAll()
}

@Dao
interface ManagedKeyDao {
  @Query("SELECT * FROM managed_keys ORDER BY createdAtIso DESC")
  fun observeAll(): Flow<List<ManagedKeyEntity>>

  @Insert(onConflict = OnConflictStrategy.REPLACE)
  suspend fun upsert(key: ManagedKeyEntity)

  @Query("DELETE FROM managed_keys WHERE keyId = :keyId")
  suspend fun deleteById(keyId: String)

  @Query("SELECT * FROM managed_keys WHERE keyId = :keyId LIMIT 1")
  suspend fun findById(keyId: String): ManagedKeyEntity?
}

@Database(
  entities = [OperationHistoryEntity::class, ManagedKeyEntity::class],
  version = 1,
  exportSchema = false,
)
abstract class AppsignDatabase : RoomDatabase() {
  abstract fun historyDao(): OperationHistoryDao
  abstract fun keyDao(): ManagedKeyDao

  companion object {
    @Volatile private var instance: AppsignDatabase? = null

    fun getInstance(context: Context): AppsignDatabase =
      instance
        ?: synchronized(this) {
          instance
            ?: Room.databaseBuilder(
                context.applicationContext,
                AppsignDatabase::class.java,
                "appsign_local.db",
              )
              .addCallback(
                object : Callback() {
                  override fun onOpen(db: SupportSQLiteDatabase) {
                    super.onOpen(db)
                    runCatching {
                      // Heal any pre-existing oversized history blobs that exceed Android's 2MB CursorWindow limit
                      db.execSQL("UPDATE operation_history SET reportJson = '' WHERE LENGTH(reportJson) > 16384")
                      db.execSQL("UPDATE operation_history SET detailsSummary = SUBSTR(detailsSummary, 1, 1024) WHERE LENGTH(detailsSummary) > 1024")
                      db.execSQL("UPDATE operation_history SET fileNames = SUBSTR(fileNames, 1, 512) WHERE LENGTH(fileNames) > 512")
                    }
                  }
                }
              )
              .build()
              .also { instance = it }
        }
  }
}
